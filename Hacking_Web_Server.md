# Lab 1: Footprint the Web Server
## Task 1: Information Gathering using Ghost Eye

	[parrot]
	sudo su
	cd  ghost_eye
	pip3 install -r requirments.txt 
	python3 ghost_eye.py
	3 -> perform whose looup
	certifiedhacker.com ->Enter Domain or IP Address
	look -
	Domain Name, Registry Domain ID, Registrar WHOIS Server, Registrar URL, and Updated Date.
	type 2 -> DNS lookup
	certifiedhacker.com
	6 -> Clickjacking
	certifiedhacker.com
---
## Task 2: Perform Web Server Reconnaissance using Skipfish

	[Win Server 22]
	search wamp, Wampserver64 appears -> enter
	Wait until the WAMP Server icon turns Green in the Notification area.

	[parrot]
	sudo su
	perform security reconnaissance on a web server using Skipfish.The target is the WordPress website http://[IP Address of Windows Server 2022].
	
	skipfish -o /home/attacker/test -S /usr/share/skipfish/dictionaries/complete.wl http://[IP Address of Windows Server 2022]:8080
	-> o/p dir test
	-> dictionary file based on the web server’s requirement
	
	On receiving this command, Skipfish performs a heavy brute-force attack on the web server by using the complete.wl dictionary file, creates a directory named test in the root location, and stores the result in index.html inside this location.
	
	Let it run for 5 mint, Ctrl+C
	
	Open /home/attacker/test/index.html -> firefox -> To view the scan result
---
## Task 3: Footprint a Web Server using the httprecon Tool

	[win 11]
	Web Server Footprinting Tools\httprecon, right-click httprecon.exe -> Run as an admin
	Website url: www.certifiedhacker.com
	port:80
	Analyze
	
	Get existing tab, and observe the server (nginx) used to develop the webpages. [attackers research the vulnerabilities present in nginx and try to exploit them, 
	which results in either full or partial control over the web application.]
	
	GET long request tab, which lists all GET requests. Next, click the Fingerprint Details tab. [include the name of the protocol the website is using and its 
	version.Attacker might perform malicious activities such as sniffing over the HTTP channel, which might result in revealing sensitive data such as user credentials.]
---
## Task 4: Footprint a Web Server using ID Serve

	[Win 11]
	Web Server Footprinting Tools\ID Serve and double-click idserve.exe.
	The main window of ID Serve appears. By default, the Server Query tab appears.
	
	enter the URL (http://www.certifiedhacker.com) you want to footprint.
	Click Query the Server to start querying the website.
---
## Task 5: Footprint a Web Server using Netcat and Telnet

**Netcat**
Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol.
**Telnet**

Telnet is a client-server network protocol. It is widely used on the Internet or LANs. It provides the login session for a user on the Internet. The single terminal attached to another computer emulates with Telnet. The primary security problems with Telnet are the following:
-It does not encrypt any data sent through the connection.    
-It lacks an authentication scheme.

	[parrot]
	sudo su
	nc -vv www.moviescope.com 80	
	GET / HTTP/1.0 -> Enter twice
	
	Netcat will perform the banner grabbing and gather information such as content type, last modified date, accept ranges, ETag, and server information.

	telnet www.moviescope.com 80
	GET / HTTP/1.0 -> Enter twice
	
	Telnet will perform the banner grabbing and gather information such as content type, last modified date, accept ranges, ETag, and server information.
---
## Task 6: Enumerate Web Server Information using Nmap Scripting Engine (NSE)

	[parrot]
	nmap -sV --script=http-enum www.goodshoping.com
	 
	 To discover the hostnames that resolve the targeted domain.
	nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- www.gooshopping.com

	Perform HTTP trace on the targeted domain
	nmap --script http-trace -d www.goodshopping.com
	This script will detect a vulnerable server that uses the TRACE method by sending an HTTP TRACE request that shows if the method is enabled or not.

	check whether Web Application Firewall is configured on the target host or domain
	nmap -p80 --script http-waf-detect www.goodshopping.com 
	determine whether a web server is being monitored by an IPS, IDS, or WAF.
	This command will probe the target host with malicious payloads and detect the changes in the response code.
---
## Task 7: Uniscan Web Server Fingerprinting in Parrot Security

	[Win server 22]
	launch wamp, Wampserver64 -> Enter
	Wait until the WAMP Server icon turns Green in the Notification area. Leave the Windows Server 2022 machine running.

	[parrot]
	sudo su
	
	uniscan -h
	uniscan -u http://10.10.1.22:8080/CEH -q
	-q -> to search for the directories of the web server.
	
	uniscan -u http://10.10.1.22:8080/CEH -we
	Here -w and -e are used together to enable the file check (robots.txt and sitemap.xml file).
	
	uniscan -u http://10.10.1.22:8080/CEH -d
	to start a dynamic scan on the web server.
	obtaining more information about email-IDs, Source code disclosures, and external hosts, web backdoors, dynamic tests.
	
	File system ->
	usr --> share --> uniscan --> report.
---
# Lab 2: Perform a Web Server Attack
## Task 1: Crack FTP Credentials using a Dictionary Attack
TO check whether ftp service is running on windows 11 m/c

[parrot]
sudo su
nmap -p 21 10.10.1.11 -> 21 is open

To check whether FTP server is hosted on win 11
ftp  10.10.1.11

You will be prompted to enter user credentials. The need for credentials implies that an FTP server is hosted on the machine.
Enter any credentials, u will not able to login. Close terminal


Perform Dictonary attack to gain access to FTP server using THC Hydra tool
Copy worklist folder from shared : to desktop

[parrot]
sudo su

hydra -L /home/attacker/Desktop/Wordlists/Usernames.txt -P /home/attacker/Desktop/Wordlists/Passwords.txt ftp://10.10.1.11
On completion of the password cracking, the cracked credentials appear

Login using credentials

ftp 10.10.1.11
Martin
apple
ftp>mkdir Hacked
ftp>help
ftp>quit

[Win 11]
C:\FTP-> view the dir name Hacked


