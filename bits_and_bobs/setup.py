#! /usr/bin/python
import os,sys,subprocess

def main(argv):

	
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

	print "[+]RedSnarf Quick and Dirty Installer"
	print "[+]Starting Install"
	os.system("apt-get update")
	os.system("apt-get install python-ipy python2.7-dev libpq-dev python-dev libxml2-dev libxslt1-dev libldap2-dev libsasl2-dev libffi-dev --fix-missing")
	os.system("pip install netaddr")
	os.system("pip install termcolor")
	os.system("pip install python-ldap")

	if not os.path.isfile('/opt/creddump7/pwdump.py'):
		os.system("git clone https://github.com/Neohapsis/creddump7 /opt/creddump7")

	if not os.path.isfile('/usr/local/bin/secretsdump.py'):
		if not os.path.isfile('/tmp/impacket/setup.py')
			os.system("git clone https://github.com/CoreSecurity/impacket.git /tmp/impacket")
		
		os.system("chmod 777 /tmp/impacket/setup.py")
		
		proc = subprocess.Popen("python /tmp/impacket/setup.py install" , stdout=subprocess.PIPE,shell=True).wait()
		stdout_value = proc.communicate()[0]
		print stdout_value

if __name__ == "__main__":
   main(sys.argv[1:])