#! /usr/bin/env python
from __future__ import print_function
import os
import sys


def main(argv):
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

    print("[+]RedSnarf Quick and Dirty Installer")
    print("[+]Starting Installation Process")
    os.system("apt-get update")
    os.system("apt-get install python-ipy python2.7-dev libpq-dev python-dev "
              "libxml2-dev libxslt1-dev libldap2-dev libsasl2-dev libffi-dev "
              "--fix-missing")
    os.system("pip install netaddr")
    os.system("pip install termcolor")
    os.system("pip install python-ldap")

    if not os.path.isfile('/opt/creddump7/pwdump.py'):
        os.system("git clone https://github.com/Neohapsis/creddump7 "
                  "/opt/creddump7")

    if not os.path.isfile('/usr/local/bin/secretsdump.py'):
        if not os.path.isfile('/tmp/impacket/setup.py'):
            os.system("git clone https://github.com/CoreSecurity/impacket.git "
                      "/tmp/impacket")

        os.system("chmod 777 /tmp/impacket/setup.py")

        print("[+]All that's left to do is run navigate to /tmp/impacket/ and "
              "run python setup.py install")
        print("[+]Bye")


if __name__ == "__main__":
   main(sys.argv[1:])
