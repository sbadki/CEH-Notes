
**Overview of Active Sniffing**

Active sniffing involves sending out multiple network probes to identify access points. The following is the list of different active sniffing techniques:

- **MAC Flooding**: Involves flooding the CAM table with fake MAC address and IP pairs until it is full

- **DNS Poisoning**: Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not

- **ARP Poisoning**: Involves constructing a large number of forged ARP request and reply packets to overload a switch

- **DHCP Attacks**: Involves performing a DHCP starvation attack and a rogue DHCP server attack

- **Switch port stealing**: Involves flooding the switch with forged gratuitous ARP packets with the target MAC address as the source

- **Spoofing Attack**: Involves performing MAC spoofing, VLAN hopping, and STP attacks to steal sensitive information
--------------
**Perform active sniffing

**Task 1: Perform MAC flooding using macof**

MAC flooding is a technique used to compromise the security of network switches that connect network segments or network devices. Attackers use the MAC flooding technique to force a switch to act as a hub, so they can easily sniff the traffic.

macof is a Unix and Linux tool that is a part of the dsniff collection. It floods the local network with random MAC addresses and IP addresses, causing some switches to fail and open in repeating mode, thereby facilitating sniffing. This tool floods the switch’s CAM tables (131,000 per minute) by sending forged MAC entries. When the MAC table fills up, the switch converts to a hub-like operation where an attacker can monitor the data being broadcast.

	[parrot]
	wireshark
	cmd> macof -i eth0 -n 10
	macof -i eth0 -d [ip]
	
	Look for IPV4 protocol - observer source and destination address in Ethernet frame.

	captured IPv4 packet and expand the Ethernet II node in the packet details section. Information regarding the source and destination MAC addresses is displayed

Macof sends the packets with random MAC and IP addresses to all active machines in the local network. If you are using multiple targets, you will observe the same packets on all target machines.

---------------------------------------------------------------------------------------------------

**Taskk 2: Perform a DHCP Starvation Attack using Yersinia**

In a DHCP starvation attack, an attacker floods the DHCP server by sending a large number of DHCP requests and uses all available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a Denial-of-Service (DoS) attack. Because of this issue, valid users cannot obtain or renew their IP addresses, and thus fail to access their network. This attack can be performed by using various tools such as Yersinia and Hyenae.

Yersinia is a network tool designed to take advantage of weaknesses in different network protocols such as DHCP. It pretends to be a solid framework for analyzing and testing the deployed networks and systems.

	[parrot]
	wireshark

	cmd>sudo su
	cd -> root dir
	yersinia -I	
	
	interactive mode appears, To remove the Notification window, press any key, and then press h for help.
	Press q to exit the help options.

	Press F2 to select DHCP mode. In DHCP mode, STP Fields in the lower section of the window change to DHCP Fields.

	Press x to list available attack options.
	The Attack Panel window appears; press 1 to start a DHCP starvation attack.
	Yersinia starts sending DHCP packets to the network adapter and all active machines in the local network

	q -> quite

	wireshark
	Click on any DHCP packet and expand the Ethernet II node in the packet details section. I

---------------------------------------------------------------------------------------------------

**Task 3: Perform ARP Poisoning using arpspoof**
ARP spoofing is a method of attacking an Ethernet LAN. ARP spoofing succeeds by changing the IP address of the attacker’s computer to the IP address of the target computer. A forged ARP request and reply packet find a place in the target ARP cache in this process. As the ARP reply has been forged, the destination computer (target) sends the frames to the attacker’s computer, where the attacker can modify them before sending them to the source machine (User A) in an MITM attack.

arpspoof redirects packets from a target host (or all hosts) on the LAN intended for another host on the LAN by forging ARP replies. This is an extremely effective way of sniffing traffic on a switch.

	[parrot]
	wireshark
	
	cmd>sudo su
	cd
	arpspoof -i eth0 -t 10.10.1.1 10.10.1.11   
	(Issuing the command informs the access point that the target system (10.10.1.11) has our MAC address (the MAC address of host machine (Parrot Security)). In 												other words, we are informing the access point that we are the target system.)
	10.10.1.1  -> access point /gateway
	10.10.1.11 -> target
	
	CTLR+ z -> stop sending ARP packets
	
	observer wireshark
	
	arpspoof -i eth0 -t 10.10.1.11 10.10.1.1 (The host system informs the target system (10.10.1.11) that it is the access point (10.10.1.1))
	CTRL+z
	
	observer wireshark

	Click on ARP packet and expand the Ethernet II node in the packet details section. Can observe the MAC addresses of IP addresses 10.10.1.1 and 10.10.1.11. [Here, 
	the MAC address of the host system (Parrot Security) is 02:15:5d:22:14:ce.]

	You will observe that the MAC addresses of IP addresses 10.10.1.1 and 10.10.1.13 are the same, indicating the occurrence of an ARP poisoning attack, where 
	10.10.11.13 is the Parrot Security machine and 10.10.1.1 is the access point.

Attackers use the arpspoof tool to obtain the ARP cache; then, the MAC address is replaced with that of an attacker’s system. Therefore, any traffic flowing from the victim to the gateway will be redirected to the attacker’s system.

---------------------------------------------------------------------------------------------------
**Task 4: Perform an Man-in-the-Middle (MITM) Attack using Cain & Abel**

Cain & Abel is a password recovery tool that allows the recovery of passwords by sniffing the network and cracking encrypted passwords. The ARP poisoning feature of the Cain & Abel tool involves sending free spoofed ARPs to the network’s host victims. This spoofed ARP can make it easier to attack a middleman.

	[windows 19]
	
	Launch Cain & Abel
	Configure -> By default Sniffer -> ensure Adapter is associated with ip of the machine is selected
	Start/stop sniffer icon
	sniffer tab

	Click the plus (+) icon or right-click in the window and select Scan MAC Addresses to scan the network for hosts.
	Check the All hosts in my subnet radio button and select the All Tests checkbox; then, click OK.

	a list of all active IP addresses along with their corresponding MAC addresses is displayed
	click the APR tab at the bottom of the window.

	Click anywhere on the topmost section in the right-hand pane to activate the plus (+) icon.

	New ARP Poison Routing window appears, from which we can add IPs to listen to traffic.
	To monitor the traffic between two systems (here, Windows 11 and Windows Server 2022), click to select 10.10.1.11 (Windows 11) from the left-hand pane and 
	10.10.1.22 (Windows Server 2022) from the right-hand pane; click OK.

	Click to select the created target IP address scan displayed in the Configuration / Routes Packets tab.

	Click on the Start/Stop APR icon to start capturing ARP packets. The Status will change from Idle to Poisoning.
	
	[win 22] -  Admin
	
	cmd>ftp 10.10.1.11
	Jason
	qwerty
	
	[Windows 2019]
	Click the Passwords tab,Click FTP from the left-hand pane to view the sniffed password for ftp 10.10.1.11

Note: In real-time, attackers use the ARP poisoning technique to perform sniffing on the target network. Using this method, attackers can steal sensitive information, prevent network and web access, and perform DoS and MITM attacks.

---------------------------------------------------------------------------------------------------
**Task 5: Spoof a MAC Address using TMAC and SMAC**
A MAC duplicating or spoofing attack involves sniffing a network for the MAC addresses of legitimate clients connected to the network. In this attack, the attacker first retrieves the MAC addresses of clients who are actively associated with the switch port. Then, the attacker spoofs their own MAC address with the MAC address of the legitimate client. Once the spoofing is successful, the attacker receives all traffic destined for the client. Thus, an attacker can gain access to the network and take over the identity of a network user.

	[Windows 11]
	launch TMAC 
	choose the network adapter of the target machine, whose MAC address is to be spoofed (here, Ethernet).
	
	Information tab, note the Original MAC Address of the network adapter
	
	Click the Random MAC Address button under the Change MAC Address option to generate a random MAC address for the network adapter.
	Click the Change Now ! button to change the MAC address.
	Observe that the newly generated random MAC address appears under the Active MAC Address section, 
	To restore the original MAC address, you can click on the Restore Original button 


	SMAC Tool:
	
	launch SMAC

	Agreement
	SMAC Registration window appears -> Proceed
	hoose the network adapter of the target machine whose MAC address is to be spoofed.
	Random button to generate a random MAC address.
	Forward arrow button (>>) under Network Connection to view the Network Adapter information.
	The Load MAC List window appears; select the SMAC/Sample_MAC_Address_List.txt file and click Open.
	The selected MAC address appears under the New Spoofed MAC Address field.
	
	Click the Update MAC button
	Once the adapter is restarted, a random MAC address is assigned to your machine. You can see the newly generated MAC address under Spoofed MAC Address and Active 
	MAC Address.

To restore the MAC address back to its original setting, click the Remove MAC button.

---------------------------------------------------------------------------------------------------
**Task 6: Spoof a MAC Address of Linux Machine using macchanger**

	[parrot]
	sudo su
	cd
	Before changing the MAC address we need to turn off the network interface.
	ifconfig eth0 down
	
	macchanger --help
	macchanger -s eth0 -> current MAC address
	macchanger -a eth0  -> -a: sets random vendor MAC address to the network interface.
	macchanger -r eth0 -> set a random MAC address to the network interface.
	ifconfig eth0 up -> enable n/w interface
	ifconfig
	End - relaunch

---------------------------------------------------------------------------------------------------
**Lab 2: Perform Network Sniffing using Various Sniffing Tools**

A packet sniffing program (also known as a sniffer) can only capture data packets from within a given subnet, which means that it cannot sniff packets from another network. Often, any laptop can plug into a network and gain access to it. Many enterprises leave their switch ports open. A packet sniffer placed on a network in promiscuous mode can capture and analyze all network traffic. Sniffing programs turn off the filter employed by Ethernet network interface cards (NICs) to prevent the host machine from seeing other stations’ traffic. Thus, sniffing programs can see everyone’s traffic.

**Task 1: Perform Password Sniffing using Wireshark**

The tool uses Winpcap to capture packets on its own supported networks. It captures live network traffic from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, and FDDI networks. The captured files can be programmatically edited via the command-line.

	[Windows 2019]
	Wireshark
	
	[Windows 11]
	http://www.moviescope.com/
	sam/test
	
	wireshark - stop capturing packets
	File save as -> password_sniff
	
	apply filter
	http.request.method == POST ->
	Edit -> Find Packet
	
	Click Display filter, select String from the drop-down options. 
	Click Packet list, select Packet details from the drop-down options, and click Narrow & Wide and select Narrow (UTF-8 / ASCII) from the drop-down options.
	pwd and Find
	Expand the HTML Form URL Encoded: application/x-www-form-urlencoded 
	Should be able to see credentials.
	
	CLose wireshark and Sign out from 11 - Admin
	
	[Windows 2019] 
	
	RDC -> 10.10.1.11 -> Jason\qwerty -> Popup OK [credentials received from earlier]
	
	Control pannel -> System and Security --> Windows Tools -> Services
	Remote Packet Capture Protocol v.0 (experimental) -> Right click -> start
	
	Close RDC of win 11 machine
	
	[Win 2019]
	
	click the Capture options icon from the toolbar.
	click the Manage Interfaces… 
	click the Remote Interfaces tab, and then the Add a remote host and its interface icon (+).
	enter the IP address of the target machine (here, 10.10.1.11); and in the Port field, enter the port number as 2002. -> OK
	
	The newly added remote interface appears in the Wireshark. Capture Options window; click Start.
		Note: Ensure that both Ethernet and rpcap interfaces are selected.
	
	[Win 11]
	Jason\qwerty -> Signing as victim
	
	http://www.goodshopping.com)
	
	[Win 19]
	Wireshark start capturing packets as soon as victim starting browsing the internet -> Look for HTTP Get req observer -> Stop

---------------------------------------------------------------------------------------------------
Task 2: Analyze a Network using the Omnipeek Network Protocol Analyzer

---------------------------------------------------------------------------------------------------
**Lab 3: Detect Network Sniffing**
possible defensive techniques used to defend a target network against sniffing attacks.

sniffers can be detected by using various techniques such as:

Ping Method: Identifies if a system on the network is running in promiscuous mode

DNS Method: Identifies sniffers in the network by analyzing the increase in network traffic

ARP Method: Sends a non-broadcast ARP to all nodes in the network; a node on the network running in promiscuous mode will cache the local ARP address

**Task 1: Detect ARP Poisoning and Promiscuous Mode in a Switch-Based Network**

Here, we will detect ARP poisoning in a switch-based network using Wireshark and we will use the Nmap Scripting Engine (NSE) to check if a system on a local Ethernet has its network card in promiscuous mode.

	[Win 19] -> host - perform ARP poisoning, to perform ARP poisoning & sniff traffic between Win 11 <--> Parrot 
	Win 19 - use same machine to detect ARP poisoning 
	Win 11- to detect promiscuous mode 
	
	[Win 19]
	launch Cain
	Follow same steps mentioned above
	After clicking on the Start/Stop APR icon, Cain & Abel starts ARP poisoning and the status of the scan changes to Poisoning.
	
	To generate traffic between the machines, you need to ping one target machine using the other.
	
	[parrot] 
	sudo su 
	cd
	hping3 10.10.1.11 -c 100000
		-c pkt count
	
	[Win19]
	Wireshark
	Edit -> preferences -> Protocol -> select the ARP/RARP option.
	click the Detect ARP request storms checkbox and ensure that the Detect duplicate IP address configuration checkbox is checked; click OK.
	double-click on the adapter associated with your network (here, **Ethernet**) to start capturing the network packets.

	Wireshark begins to capture the traffic between the two machines.
	
	Cain & Abel -> observe the packets flowing between the two machines. [Check no of packets]
	
	Stop packet capture in wireshark
	
	Click Analyze from the menu bar and select Expert Information
	click to expand the Warning node labeled Duplicate IP address configured (10.10.1.11), running on the ARP/RARP protocol.
	
	Arrange the Wireshark . Expert Information window above the Wireshark window so that you can view the packet number and the Packet details section.
	In the Wireshark . Expert Information window, click any packet (here, 138).
	
	On selecting the packet number, Wireshark highlights the packet, and its associated information is displayed under the packet details section. Close the Wireshark . Expert Information window.
	
	The warnings highlighted in yellow indicate that duplicate IP addresses have been detected at one MAC address, as shown in the screenshot.


Note: ARP spoofing succeeds by changing the IP address of the attacker’s computer to the IP address of the target computer. A forged ARP request and reply packet find a place in the target ARP cache in this process. As the ARP reply has been forged, the destination computer (target) sends frames to the attacker’s computer, where the attacker can modify the frames before sending them to the source machine (User A) in an MITM attack. At this point, the attacker can launch a DoS attack by associating a non-existent MAC address with the IP address of the gateway or may passively sniff the traffic, and then forward it to the target destination.

**perform promiscuous mode detection using Nmap.**

	[Win 11]
	launch zenmap
	command 
	nmap --script=sniffer-detect 10.10.1.19 -> Scan

	Likely in promiscuous mode under the Host script results section.This indicates that the target system is in promiscuous mode.

---------------------------------------------------------------------------------------------------
Task 2: Detect ARP Poisoning using the Capsa Network Analyzer

---------------------------------------------------------------------------------------------------
