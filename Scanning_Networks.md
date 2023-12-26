104.21.15.19 - kits.edu
162.241.216.11 - certifiedhacker.com

Lab Tasks
Ethical hackers and pen testers use numerous tools and techniques to scan the target network. Recommended labs that will assist you in learning various network scanning techniques include:

1. **Perform host discovery**
   **host discovery techniques:**

ARP ping scan
UDP ping scan
ICMP ping scan (ICMP ECHO ping, ICMP timestamp, ping ICMP, and address mask ping)
TCP ping scan (TCP SYN ping and TCP ACK ping)
IP protocol ping scan

	i. Perform host discovery using Nmap
```
└──╼ #nmap -sn **-PR** 162.241.216.11 --> ARP ping scan
└──╼ #nmap -sn -PU 162.241.216.11  --> UDP ping scan
└──╼ #nmap -sn -PE 162.241.216.11  -->ICMP ECHO ping,
└──╼ #nmap -sn -PP 162.241.216.11  -->ICMP timestamp ping
└──╼ #nmap -sn -PS 162.241.216.11    TCP SYN Ping Scan
```
[sends empty TCP SYN packets to the target host, ACK response means that the host is active.]
`└──╼ #nmap -sn -PA 162.241.216.11     TCP ACK Ping Scan:`
[sends empty TCP ACK packets to the target host; an RST response means that the host is active.]
`└──╼ #nmap -sn -PM 162.241.216.11	ICMP Address Mask Ping Scan`
[This technique is an alternative for the traditional ICMP ECHO ping scan, which are used to determine whether the target host is live specifically when administrators block the ICMP ECHO pings.]
`└──╼ #nmap -sn -PO 162.241.216.11  	IP Protocol Ping Scan`
[sends different probe packets of different IP protocols to the target host, any response from any probe indicates that a host is active.]

**[To determine the live hosts from a range of IP addresses]**
```
└──╼ #nmap -sn -PE 104.21.15.**0-255**  -->ICMP ECHO ping sweep
└──╼ #nmap -sn -PE 162.241.216.0/24
```

ii. Perform host discovery using Angry IP Scanner** [windows]
2.	**Perform port and service discovery**

i. Perform port and service discovery using MegaPing[windows]
ii. Perform port and service discovery using NetScanTools Pro[windows]
**iii. Perform port scanning using sx tool**

sx arp 10.10.1.0/24 --json | tee arp.cache
cat arp.cache | sx tcp -p 1-65535 10.10.1.11
cat arp.cache | sx udp -p 53 10.10.1.11
OR
cat **arp.cache** | sx udp --json -p 500 10.10.1.11

iv. Explore various network scanning techniques using Nmap
```
nmap -sT -v 10.0.2.15
...
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

[stealth scan/TCP half-open scan] [windows server 2022 machine and keep firewall on ]
nmap -sS -v 10.0.2.15

[The stealth scan involves resetting the TCP connection between the client and server abruptly before completion of three-way handshake signals, and hence leaving the connection half-open. This scanning technique can be used to bypass firewall rules, logging mechanisms, and hide under network traffic.]
nmap -sX -v 10.0.2.15
[Xmas scan sends a TCP frame to a target system with FIN, URG, and PUSH flags set. If the target has opened the port, then you will receive no response from the target system. If the target has closed the port, then you will receive a target system reply with an RST.]
nmap -sM -v 10.0.2.15
[In the TCP Maimon scan, a FIN/ACK probe is sent to the target; if there is no response, then the port is Open|Filtered, but if the RST packet is sent as a response, then the port is closed.]
nmap -sA -v 10.0.2.15
[The ACK flag probe scan sends an ACK probe packet with a random sequence number; no response implies that the port is filtered (**stateful firewall is present**), and an RST response means that the port is not filtered.]

[**Only SYN scan showed me the ports open**]
nmap -sU -v 10.0.2.15
[The UDP scan uses UDP protocol instead of the TCP. There is no three-way handshake for the UDP scan. It sends UDP packets to the target host; no response means that the port is open. If the port is closed, an ICMP port unreachable message is received.]
```
Host is up (0.00042s latency).
Not shown: 992 closed udp ports (port-unreach)
PORT     STATE         SERVICE
123/udp  open|filtered ntp
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
1900/udp open|filtered upnp
4500/udp open|filtered nat-t-ike
5050/udp open|filtered mmcc
5353/udp open|filtered zeroconf
5355/udp open|filtered llmnr
```

Null scan: - created new profile
`nmap -sN -T4 -A -v 10.0.2.15`
Service versoin scan
```
nmap -sV 162.241.216.11

Host is up (0.24s latency).
Not shown: 984 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 7.4 (protocol 2.0)
25/tcp   open     smtp       Exim smtpd 4.96.2
26/tcp   open     smtp       Exim smtpd 4.96.2
53/tcp   open     domain     ISC BIND 9.11.4-P2 (RedHat Enterprise Linux 7)
80/tcp   open     http       Apache httpd
110/tcp  open     pop3       Dovecot pop3d
143/tcp  open     imap       Dovecot imapd
443/tcp  open     ssl/http   Apache httpd
465/tcp  open     tcpwrapped
587/tcp  open     tcpwrapped
993/tcp  open     ssl/imap   Dovecot imapd
995/tcp  open     ssl/pop3   Dovecot pop3d
2222/tcp open     ssh        OpenSSH 7.4 (protocol 2.0)
3306/tcp open     mysql      MySQL 5.7.23-23
5432/tcp open     postgresql PostgreSQL DB
```
Aggressive scan
`nmap -T4 -A -v 162.241.216.11`
The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute). [You should not use -A against target networks without permission.]

v. Explore various network scanning techniques using Hping3
Hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols.

Mode
default mode     TCP
-0  --rawip      RAW IP mode
-1  --icmp       ICMP mode
-2  --udp        UDP mode
-8  --scan       SCAN mode.
Example: hping --scan 1-30,70-90 -S www.target.host
-9  --listen     listen mode

```
hping3 -A 10.0.2.15 -p 80 -c 5					ACK Scan
hping3 -8 0-100 -S 10.0.2.15 -V				 Scan mode
hping3 -8 0-100 -S 162.241.216.11 -V
hping3 -F -P -U 10.0.2.15 -p 80 -c 5  (-c packet count)
hping3 --scan 0-100 -S 10.0.2.15			 (port range to scan, 0-100 specifies the range of ports to be scanned,)
hping3 -1 10.0.2.15 -p 80 -c 5					ICMP scan
hping3 -2 10.2.0.15 -p 80 -c 5					UDP scan
```

[the number of packets sent and received is equal, thereby indicating that the respective port is **open**]

3. **Perform OS discovery**
   There are two types of OS discovery or banner grabbing techniques:

**Active Banner Grabbing** Specially crafted packets are sent to the remote OS, and the responses are noted, which are then compared with a database to determine the OS. Responses from different OSes vary, because of differences in the TCP/IP stack implementation.

**Passive Banner Grabbing** This depends on the differential implementation of the stack and the various ways an OS responds to packets. Passive banner grabbing includes banner grabbing from error messages, sniffing the network traffic, and banner grabbing from page extensions.

The TTL field determines the maximum time a packet can remain in a network, and the TCP window size determines the length of the packet reported.

![09c639f7a9e43fe3aecc0da2d20c0404.png](:/51cfa1cafebd48e08d79e65aa0f437e3)

i. **Identify the target system’s OS with Time-to-Live (TTL) and TCP window sizes using Wireshark**
`Time to Live: 127`

ii. **Perform OS discovery using Nmap Script Engine (NSE)**


iii. **Perform OS discovery using Unicornscan**
4. **Scan beyond IDS and Firewall**

i. Scan beyond IDS/firewall using various evasion techniques
ii. Create custom packets using Colasoft Packet Builder to scan beyond the IDS/firewall
iii. Create custom UDP and TCP packets using Hping3 to scan beyond the IDS/firewall

5. **Perform network scanning using various scanning tools**

   **Scan a target network using Metasploit**
   sudo su
   service postgresql start
   msfconsole
   db_status
   if no conn
   exit
   msfdb init
   service postgresql restart
   msfconsole
   nmap -Pn -sS -A -oX Test 10.10.1.0/24
   db_import Test
   hosts
   services or db_services
   search portscan
   **SYN scan**
   use auxiliary/scanner/portscan/syn
   set INTERFACE eth0
   set PORT 80
   set RHOST 10.10.1.5-23
   set THREADS 50
   run
   **TCP scan**
   use auxiliary/scanner/portscan/tcp
   set RHOSTs 10.10.1.22
   run

**which version of Windows is running on a target and which Samba version is on a Linux host.**

use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.1.5-23
set THREADS 11
run

