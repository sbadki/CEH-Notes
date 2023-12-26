# Module 02: Footprinting and Reconnaissance

1.  Perform footprinting through search engines
    - Gather information using advanced Google hacking techniques 
- google.com :
                                                                   inurl:login site:eccouncil.org
                                                                   allinurl:login site:eccouncil
                                                                   allintext:login site:eccouncil.com

**2.  - Gather information from video search engines**
youtube.com --> search any video of eccouncil copy link
mattw.io --> metadata --> paste the copied link and see the video details
**- Gather information from FTP search engines**
--> https://www.**searchftps**.net/
get info about any site like facebook/microsoft can see critical files from the organisation
**- Gather information from IoT search engines**
https://www.**shodan.io**/search?query=citi
https://search.**censys.io**/hosts/170.61.77.47
**3.  Perform footprinting through web services**
**- Find the company’s domains and sub-domains using Netcraft**
https://www.netcraft.com --> Resources -> Tools -> Site Report.
- Gather personal information using PeekYou online people search service
peekyou.com,https://www.spokeo.com), pipl (https://pipl.com), Intelius (https://www.intelius.com), BeenVerified (https://www.beenverified.com)
**- Gather an email list using theHarvester**
PARROT OS:
Install and dependencies:
Python 3.9+
https://github.com/laramies/theHarvester/wiki/Installation

`──╼ $python3 theHarvester.py -d microsoft.com -l 200 -b baidu`

**- Gather information using deep and dark web searching**
Tor browser
intext:"ethical hacker for hire"

**- Determine target OS through passive footprinting**
- netcraft.com
- shodan.io
- censys.io

**3.  Perform footprinting through social networking sites**
- Gather employees’ information from LinkedIn using theHarvester
python3 theHarvester.py -d microsoft.com -l 200 -b baidu
No results:
- Gather personal information from various social networking sites using Sherlock
└──╼ $python3 sherlock satya nadella

**4.  Perform website footprinting
- Gather information about a target website using ping command line utility**
ping www.kits.edu
IP address of the target website, -->
hop count to the target, and -->18
value of maximum frame size allowed on the target network --> 1472
**- Gather information about a target website using Photon**
Install photon:

	photon -u http://www.kits.edu -l 3 -t 200 --wayback
	cd www.kits.edu
	 
    **- Gather information about a target website using Central Ops**

**- Extract a company’s data using Web Data Extractor
- Mirror a target website using HTTrack Web Site Copier
- Gather information about a target website using GRecon

[Recon searches for available subdomains, sub-subdomains, login pages, directory listings, exposed documents, WordPress entries and pasting sites and displays the results.	]
cd GRecon
python3 grecon.py
**- Gather a wordlist from the target website using CeWL****
A unique wordlist from the target website

		└──╼ $cewl -d 2 -m 5 https://www.kits.edu

**5.  Perform email footprinting [NOT DONE - setup issue]
- Gather information about a target by tracing emails using eMailTrackerPro**

**6.  Perform Whois footprinting**
- Perform Whois lookup using DomainTools
--> owner, its registrar, registration details, name server, contact information
[Windows]
https://whois.domaintools.com/

**7.  Perform DNS footprinting
- Gather DNS information using nslookup command line utility and online tool**

C:\Users\sbadki>nslookup
Default Server:  OpenWrt    [Response coming from default server that's why its non-authoritative answer.]
Address:  10.0.0.1
**> set type=a   [obtain the domain's authoritative name server]
> www.kits.edu**
Server:  OpenWrt
Address:  10.0.0.1

Non-authoritative answer:
Name:    www.kits.edu
Addresses:  104.21.15.19
172.67.161.7

**> set type=cname**
**> www.kits.edu**
Server:  OpenWrt
Address:  10.0.0.1

kits.edu
primary name server = **benedict.ns.cloudflare.com**  [domain’s authoritative name server]
responsible mail addr = dns.cloudflare.com   [mail server]
serial  = 2320856235
refresh = 10000 (2 hours 46 mins 40 secs)
retry   = 2400 (40 mins)
expire  = 604800 (7 days)
default TTL = 1800 (30 mins)
**> set type=a   [ip address of authoratative server]
> benedict.ns.cloudflare.com**
Server:  OpenWrt
Address:  10.0.0.1

Non-authoritative answer:
Name:    benedict.ns.cloudflare.com
Addresses:  **172.64.35.205
108.162.195.205
162.159.44.205**

[Note: So, if an attacker can determine the authoritative name server (primary name server) and obtain its associated IP address, he/she might attempt to exploit the server to perform attacks such as DoS, DDoS, URL Redirection, etc.]

**- Perform reverse DNS lookup using reverse IP domain check and DNSRecon**
[Windows]
https://www.yougetsignal.com/
got ip - 104.21.15.19
[Parrot]
**- Gather information of subdomain and DNS records using SecurityTrails**
[Accepts only organizational email so can't check]

**8.  Perform network footprinting []**
- Locate the network range
https://search.arin.net/rdap/?query=162.24.216.11

**- Perform network tracerouting in Windows and Linux Machines**
[Network tracerouting is a process of identifying the path and hosts lying between the source and destination. Network tracerouting provides critical information such as the IP address of the hosts lying between the source and destination, which enables you to map the network topology of the organization. Traceroute can be used to extract information about network topology, trusted routers, firewall locations, etc.]
[parrot]
tracert www.kits.edu
tracert www.kits.edu -m 5
[windows]
traceroute www.kits.edu
traceroute -h 5 www.kits.edu

**9.  Perform footprinting using various footprinting tools**
**- Footprinting a target using Recon-ng**
web reconnaissance framework with independent modules and database interaction that provides an 	environment in which open-source web-based reconnaissance can be conducted.

[*] **ftp.kits.edu** => (A) 172.67.161.7
[*] ftp2.kits.edu => No record found.
[*] Country: None
[*] Host: ftp.kits.edu
[*] Ip_Address: 172.67.161.7

[*] Host: **mail.kits.edu**
[*] Ip_Address: 104.21.15.19

[*] Host: **www.kits.edu**
[*] Ip_Address: 104.21.15.19

-------
SUMMARY
-------
[*] 6 total (6 new) hosts found.

[recon-ng][CEH][brute_hosts] >

[recon-ng][default] > marketplace install all
[recon-ng][default] > modules search
[recon-ng][default] > workspaces create CEH
[recon-ng][CEH] > workspaces list
[recon-ng][CEH] > db insert domains
domain (TEXT): kits.edu
notes (TEXT):
[*] 1 rows affected.
[recon-ng][CEH] > show domains

+-----------------------------------------+
| rowid |  domain  | notes |    module    |
+-----------------------------------------+
| 1     | kits.edu |       | user_defined |
+-----------------------------------------+
[recon-ng][CEH] > modules search brute
[recon-ng][CEH] > modules load recon/domains-hosts/brute_hosts
[recon-ng][CEH][brute_hosts] > run
[recon-ng][CEH] > back

**For Reporting:**

See what are the options available to the command
[recon-ng][default] > modules load reporting/html
[recon-ng][default][html] >
back       db         goptions   info       keys       **options**    reload     script     show       
dashboard  exit       help       input      modules    pdb        run        shell      spool      
[recon-ng][default][html] > options
list   **set**    unset  
[recon-ng][default][html] > options set
CREATOR   CUSTOMER  FILENAME  SANITIZE  
[recon-ng][default][html] > options set FILENAME /home/sbadki/Desktop/result.html
FILENAME => /home/sbadki/Desktop/result.html
[recon-ng][default][html] > options set C
CREATOR   CUSTOMER  
[recon-ng][default][html] > options set CREATOR sbadki
CREATOR => sbadki
[recon-ng][default][html] > options set CUSTOMER certifiedhacker
CUSTOMER => certifiedhacker
[recon-ng][default][html] >run
-
[The recon/domains-contacts/whois_pocs module extracts the contacts associated with the domain and displays them, as shown in the screenshot]

[recon-ng][recon-test] > modules load recon/domains-contacts/whois_pocs
[recon-ng][recon-test][whois_pocs] > options set SOURCE facebook.com
[recon-ng][recon-test][whois_pocs] > run
------------
FACEBOOK.COM
------------
[*] URL: http://whois.arin.net/rest/pocs;domain=facebook.com
[*] URL: http://whois.arin.net/rest/poc/BST184-ARIN
[*] Country: United States
[*] Email: bstout@facebook.com
[*] First_Name: Brandon
[*] Last_Name: Stout
[*] Middle_Name: None
[*] Notes: None
[*] Phone: None
[*] Region: Chicago, IL
[*] Title: Whois contact
[*] --------------------------------------------------
[*] URL: http://whois.arin.net/rest/poc/OPERA82-ARIN
[*] Country: United States
[*] Email: domain@facebook.com
[*] First_Name: None
[*] Last_Name: Operations
[*] Middle_Name: None
[*] Notes: None
[*] Phone: None
[*] Region: Menlo Park, CA
[*] Title: Whois contact
[*] --------------------------------------------------

-------
SUMMARY
-------
[*] 2 total (2 new) contacts found.
[recon-ng][recon-test][whois_pocs] >

**To extract a list of subdomains and IP addresses associated with the target URL, we need to load the recon/domains-hosts/hackertarget module.**

[recon-ng][recon-test][hackertarget] > modules load recon/domains-hosts/hackertarget
[recon-ng][recon-test][hackertarget] > options set SOURCE certifiedhacker.com
[recon-ng][recon-test][hackertarget] > run

-
    - Footprinting a target using Maltego
    - Footprinting a target using OSRFramework
    - Footprinting a target using FOCA
    - Footprinting a target using BillCipher
    - Footprinting a target using OSINT Framework
-------------

[Identify ip addres of the site]
└──╼ $ping www.kits.edu
PING www.kits.edu (**104.21.15.19**) 56(84) bytes of data.

traceroute/tracert www.kits.edu
└──╼ $traceroute www.kits.edu
traceroute to www.kits.edu (**104.21.15.19**), 30 hops max, 60 byte packets
