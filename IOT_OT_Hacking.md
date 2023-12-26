# Lab 1: Perform Footprinting using Various Footprinting Techniques
## Task 1: Gather Information using Online Footprinting Tools
	[Win 11]
	luanch Firefox: https://www.whois.com/whois/ 
	www.oasis-open.org -> search
	
	Note: Oasis is an organization that has published the MQTT v5.0 standard, which represents a significant leap in the refinement and capability of the messaging 
	protocol that already powers IoT.
	
	New tab:https://www.exploit-db.com/google-hacking-database
	type SCADA in the Quick Search
	
	new tab: https://www.google.com
	"login" intitle:"scada login"
	click any link (here, SCADA :: seamtec SCADA login ::)
	seamtec SCADA login page appears -> can brute-force the credentials to gain access to the target SCADA system
	use advanced search operators such as intitle:"index of" scada to search sensitive SCADA directories that are exposed on sites.
	
	New tab:https://account.shodan.io/login 
	enter credentials -> Register if no credentials
	
	Shodan main page appears; type port:1883 
		Note: Port 1883 is the default MQTT port; 1883 is defined by IANA as MQTT over TCP.
	displaying the list of IP addresses having port 1883 enabled
	Click on any IP address to view its detailed information. -> displaying information regarding Ports, Services, Hostnames, ASN,
	
	Search for Modbus-enabled ICS/SCADA systems:
	
	port:502
	
	Search for SCADA systems using PLC name:
	
	“Schneider Electric”
	
	Search for SCADA systems using geolocation:
	
	SCADA Country:"US"
	
	Using Shodan, you can obtain the details of SCADA systems that are used in water treatment plants, nuclear power plants, HVAC systems, electrical transmission 
	systems, home heating systems, etc.
---
# Lab 2: Capture and Analyze IoT Device Traffic
If the cameras use the default factory credentials, an attacker can easily intercept all the traffic flowing between the camera and web applications and further gain access to the camera itself. Attackers can use tools such as Wireshark to intercept such traffic and decrypt the Wi-Fi keys of the target network.

## Task 1: Capture and Analyze IoT Traffic using Wireshark
	[Win server 2019]
	Run \Bevywise IoT Simulator\Bevywise_MQTTRoute_Win_64.exe file.
	
	The MQTTRoute will execute and the command prompt will appear. You can see the TCP port using 1883.
	
	To create IoT devices, we must install the IoT simulator on the client machine.
	[Win server 2022]
	
	Run \Bevywise IoT Simulator\Bevywise_IoTSimulator_Win_64.exe
	Launch C:\Bevywise\IotSimulator\bin\runsimulator.bat
	How do you want to open this? pop-up appears, select Microsoft Edge browser and click OK to open the URL http://127.0.0.1:9000/setnetwork?network=HEALTH_CARE.
	View the default network named HEALTH_CARE and several devices.
	
	Create a virtual IoT network and virtual IoT devices. 
	select the +New Network option.
	CEH_FINANCE_NETWORK ->Create.
	Broker IP Address as 10.10.1.19 
	 Since we have installed the Broker on the web server, the created network will interact with the server using MQTT Broker.
	To add IoT devices to the created network, click on the Add blank Device button.
	Device name:Temperature_Sensor, enter Device Id:TS1, Description and click on Save.
	To connect the Network and the added devices to the server or Broker, click on the Start Network red color circular icon in right corner.
	
	When a connection is established between the network and the added devices and the web server or the MQTT Broker, the red button turns into green.
	
	[Win server 19]
	Since the Broker was left running, you can see a connection request from machine 10.10.1.22 for the device TS1.
	
	[Win server 22]
	Next, we will create the Subscribe command for the device Temperature_Sensor.
	Click on the Plus icon in the top right corner and select the Subscribe to Command option.
	The Subscribe for command - TS1 popup opens. Select On start under the Subscribe on tab, type High_Tempe under the Topic tab, and select 1 Atleast once below the 
	Qos option. Click on Save.
	can see the Topic added under the Subscribe to Commands section.
	 will capture the traffic between the virtual IoT network and the MQTT Broker to monitor the secure communication.
	
	 Wireshark
	 Note: Make sure you have selected interface which has 10.10.1.22 as the IP address.
	
	[Win server 2019]
	Minimise all opened applications and windows, Open Chrome browser, type http://localhost:8080 and press Enter.
		Note: Do not use Internet Explorer web browser to open the above URL.
	Signin
	Devices Menu 
	send the command to TS1 using the High_Tempe topic.
	Command Send section, select Topic as High_Tempe, type Alert for High Temperature and click on the Send button.
	
	[Win server 22]
	Verify the message is received
	
	wireshark
	filter: mqtt
