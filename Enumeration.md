[***NetBIOS** (ports: 137/udp and 137/tcp) -- list of comp, shares, hosts, policies & password
**SNMP** (udp 161/162): maintains and manages routers, hubs, and switches on an IP network
LDAP - enumeration using Active Directory Explorer
-- ldapsearch
**DNS enumeration**(53)
**RPC**
RPC EPM                  TCP 135
RPC over HTTPS           TCP 593
SMB (for named pipes)    TCP 445
**SMB**(445)
**FTP** (21)
**SMTP(25)**
*]
NetBIOS enumeration allows you to collect information about the target such as a list of computers that belong to a target domain, shares on individual hosts in the target network, policies, passwords, etc.

NetBIOS stands for Network Basic Input Output System. Windows uses NetBIOS for file and printer sharing. A NetBIOS name is a unique computer name assigned to Windows systems, comprising a 16-character ASCII string that identifies the network device over TCP/IP. The first 15 characters are used for the device name, and the 16th is reserved for the service or name record type.

Lab Tasks
Ethical hackers or penetration testers use several tools and techniques to enumerate the target network. Recommended labs that will assist you in learning various enumeration techniques include:

**Perform NetBIOS enumeration

1. **Perform NetBIOS enumeration using Windows command-line utilities

[windows server 11]
```
nbstat -a 10.10.1.11  [-a displays the NetBIOS name table of a remote computer.]
nbstat -c  	[lists the contents of the NetBIOS name cache of the remote computer.]
net use  -->The output displays information about the target such as connection status, shared folder/drive and network information
```


3. Perform NetBIOS enumeration using NetBIOS Enumerator
   [Note: Ensure that the IP address in to field is between 10.10.1.100 to 10.10.1.250. If the IP address is less than 10.10.1.100, the tool might crash.]
   `just give range of ip's to scan, if any of the machine has netbios running it will list under the ip`

4. Perform NetBIOS enumeration using an NSE Script
```
nmap -sV -v --script nbstat.nse 10.10.1.22
nmap -sU -p 137 --script nbstat.nse 10.10.1.22
```

SNMP (Simple Network Management Protocol) is an application layer protocol that runs on UDP (User Datagram Protocol) and maintains and manages routers, hubs, and switches on an IP network. SNMP agents run on networking devices on Windows and UNIX networks.

SNMP enumeration uses SNMP to create a list of the user accounts and devices on a target computer. SNMP employs two types of software components for communication: the SNMP agent and SNMP management station. The SNMP agent is located on the networking device, and the SNMP management station communicates with the agent.

**Perform SNMP enumeration**

First, check whether the snmp service is running on the host
nmap -sU -161 -v 10.10.1.22

1. **Perform SNMP enumeration using snmp-check

`snmp-check 10.10.1.22`
provide details about: Network information, Network interfaces, Network IP and Routing information, and TCP connections and listening ports.

2. Perform SNMP enumeration using SoftPerfect Network Scanner

```
Option --> select all options -->Shared Resources, IP Address, MAC Address, Response Time, Host Name, Uptime, and System Description of the machine corresponding to the selected IP address.
Scan all ports: 10.10.1.5 - 10.10.1.23
After the results right click properties - able to view all the required details
Right click Open Device--> login as remote --> I was able to login remotely to Windows 22 server with credentials.
```

3. Perform SNMP enumeration using SnmpWalk
   –v: specifies the SNMP version number (1 or 2c or 3) and –c: sets a community string.
   [parrot]
   `snmpwalk -V1 -c public 10.10.1.22
   snmpwalk -V2c -c public 10.10.1.22
   snmpwalk -V3 -c public 10.10.1.22

4. Perform SNMP enumeration using Nmap
   snmp-desc
   snmp-win32-services
   snmp-win3-shares
   snmp-interfaces
```
nmap -sU -p 161 10.10.1.22    [check if snmp service is open]
nmap -sU -p 161 --script snmp-win32-shares 10.10.1.22
nmap -sU -p 161 --script snmp-win32-services 10.10.1.22
nmap -sU -p 161 --script snmp-interfaces 10.10.1.22
nmap -sU -p 161 --script snmp-sysdescr 10.10.1.22
```

perform LDAP enumeration to access directory listings within Active Directory or other directory services. Directory services provide hierarchically and logically structured information about the components of a network, from lists of printers to corporate email directories. In this sense, they are similar to a company’s org chart.

**Perform LDAP enumeration****

1. **Perform LDAP enumeration using Active Directory Explorer (AD Explorer)
   `list of ip's 10.10.1.5-10.10.1.23 to scan`

can modify Users details

2. Perform LDAP enumeration using Python and Nmap
```
nmap -sU -p 389 10.10.1.22 	[check in service is running]
nmap -p 389 --script-help=ldap*
nmap -p 389 --script ldap-brute --script-args ldap-base=''"cn=users,dc=CEH,dc=com"'' 10.10.1.22
```

```
python3
import ldap3
server=ldap3.Server('10.10.1.22',get_info=ldap3.ALL,port=389)
connection=ldap3.Connection(server)
connection.bind()
==>True
server.info
connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=*))',search_scope='SUBTREE',attributes='*')
connection.entries
connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=person))',search_scope='SUBTREE', attributes='userpassword') 
connection.entries
```

3. Perform LDAP enumeration using ldapsearch
   [parrot]
   `ldapsearch -h 10.10.1.22 -x -s base namingcontexts`

Note: -x: specifies simple authentication, -h: specifies the host, and -s: specifies the scope.
`ldapsearch -h 10.10.1.22 -x -b “DC=CEH,DC=com”`
`ldapsearch -x -h 10.10.1.22 -b “DC=CEH,DC=com” "objectclass=*"`

Attackers use ldapsearch for enumerating AD users. It allows attackers to establish connection with an LDAP server to carry out different searches using specific filters.

**Perform NFS enumeration****

- Perform NFS enumeration using RPCScan and SuperEnum

[RPCScan communicates with RPC (remote procedure call) services and checks misconfigurations on NFS shares. It lists RPC services, mountpoints,and directories accessible via NFS. It can also recursively list NFS shares. SuperEnum includes a script that performs a basic enumeration of any open port, including the NFS port (2049).]

Enable nfs on 2019 machine first
[Windows server 2019]
Server manager --> Roles --> Installation type -- NFS
[parrot]
if its up go ahead with SperEnum
```
cd SuperEnum
nmap 2049 10.10.1.19
echo "10.10.1.19" >> target.txt
./superenum 
target.txt
cd..
```

RPCSan
```
cd RPCScan
python3 rpc-scan.py 10.10.1.19 --rpc
```

DNS enumeration techniques are used to obtain information about the DNS servers and network infrastructure of the target organization. DNS enumeration can be performed using the following techniques:

Zone transfer
DNS cache snooping
DNSSEC zone walking

**Perform DNS enumeration****

1. 	**Perform DNS enumeration using zone transfer

DNS zone transfer is the process of transferring a copy of the DNS zone file from the primary DNS server to a secondary DNS server. In most cases, the DNS server maintains a spare or secondary server for redundancy, which holds all information stored in the main server.

If the DNS transfer setting is enabled on the target DNS server, it will give DNS information; if not, it will return an error saying it has failed or refuses the zone transfer.
**DNS enumeration of Linux DNS servers.**

`dig ns www.certifiedhacker.com`		[the dig command is used to query the DNS name servers to retrieve information about target host addresses, name servers, mail exchanges, etc.]
`dig @ns1.bluehost.com certifiedhacker.com **axfr**`

**DNS enumeration on Windows DNS servers.**
[windows 11]
```
nslookup
set querytype=soa
certifiedhacker.com
ls -d ns1.bluehost.com
```

ls -d requests a zone transfer of the specified name server.

DNSSEC zone walking is a DNS enumeration technique that is used to obtain the internal records of the target DNS server if the DNS zone is not properly configured. The enumerated zone information can assist you in building a host network map.
There are various DNSSEC zone walking tools that can be used to enumerate the target domain’s DNS record files.
Here, we will use the **DNSRecon** tool to perform DNS enumeration through DNSSEC zone walking.

2. 	Perform DNS enumeration using DNSSEC zone walking
      [parrot]

```
cd dnsrecon
chmod +x dnsrecon.py
./dnsrecon.py -d www.certifiedhacker.com -z
```
the attacker can enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF, and TXT). These DNS records contain digital signatures based on public-key cryptography to strengthen authentication in DNS.

3. 	Perform DNS enumeration using Nmap
      broadcast-dns-service-discovery
      dns-service-discovery
      dns-srv-enum
      dns-brute
```
nmap --script broadcast-dns-service-discovery 10.10.1.22
nmap -T4 -p 53 --script dns-brute certifiedhacker.com
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='certifiedhacker.com'" 10.10.1.22
```
Using this information, attackers can launch web application attacks such as injection attacks, brute-force attacks and DoS attacks on the target domain

**Perform SMTP Enumeration****
SMTP enumeration is performed to obtain a list of valid users, delivery addresses, message recipients on an SMTP server.
The Simple Mail Transfer Protocol (SMTP) is an internet standard based communication protocol for electronic mail transmission. Mail systems commonly use SMTP with POP3 and IMAP, which enable users to save messages in the server mailbox and download them from the server when necessary. SMTP uses mail exchange (MX) servers to direct mail via DNS. It runs on TCP port 25, 2525, or 587.
1. **Perform SMTP enumeration using Nmap

Using this information, the attackers can perform password spraying attacks to gain unauthorized access to the user accounts.

smtp-open-relay
smtp-enum-users
smtp-commands
smtp-brute
```
nmap -p 25 --script smtp-enum-users 10.10.1.19
nmap -p 25 --script smtp-open-relay 10.10.1.19
nmap -p 25 --script smtp-brute certifiedhacker.com
nmap --script smtp-commands certifiedhacker.com
```

**Perform RPC, SMB, and FTP enumeration****

1. **Perform SMB and RPC enumeration using NetScanTools Pro
   [windows 11]

2. Perform RPC, SMB, and FTP enumeration using Nmap
   [windows server 19]  -- make sure the ftp is enabled on the vulnerable machine (windows 19)
   Create folder c:\ftp_data
   search iis -> Open -> expand -> FTP site name : CEH.com, physical path: c:\ftp_site_data
   Binding:
   10.10.1.19 : 21
   SSL --> No SSL
   All section --> all uses
   Read+writer option select
   [parrot]

nmap -p 445 -A 10.10.1.19
nmap -p 21 -A 10.10.1.19

**Perform enumeration using various enumeration tools****

1. **Enumerate information using Global Network Inventory
   [windows server 2019]
   **2. Enumerate network resources using Advanced IP Scanner
   [windows server 2019]
   **3. Enumerate information from Windows and Samba hosts using Enum4linux

enum4linux -u martin -p apple -n 10.10.1.22		host
enum4linux -u martin -p apple -U 10.10.1.22		User policy
enum4linux -u martin -p apple -o 10.10.1.22		OS info
enum4linux -u martin -p apple -P 10.10.1.22 	-P retrieves the password policy information.
enum4linux -u martin -p apple -G 10.10.1.22		G retrieves group and member list.
enum4linux -u martin -p apple -S 10.10.1.22		S retrieves sharelist.


