# Lab 1: Encrypt the Information using Various Cryptography Tools

## Task 1: Calculate One-way Hashes using HashCalc

	[Win 11]
	Launch hashcalc
	Create a file hashcalc.txt on desktop with content - Hello world!!!
	HashCalc -> open file -> hashcalc.txt -> calculate
	
	Update content of hashcalc.txt to Hello world123!!!!
	Open new Hashcalc window -> open file -> hashcalc.txt -> calculate
	
	Could see the calculated hashes are different.
---
## Task 2: Calculate MD5 Hashes using MD5 Calculator

	[Win 11]
	Install C:\Users\sbdaki\Desktop\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\MD5 Calculator\md5calculator_setup

	Launch MD5 calculator -> Add Files -> select Desktop/sample.txt [File content - Hello world!!] -> calculate -> copy MD5 value
	Update contents of sample.txt -> [content - Hello world123!!!] -> Calculate 
	Paste the earlier calculated MD5 in Verify MD5 value and compare -> It doesn't match.
---
## Task 3: Calculate MD5 Hashes using HashMyFiles

	[Win 11]
	Open an application C:\Users\sbdaki\Desktop\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\HashMyFiles\HashMyFiles
	File -> Add folder -> Select files from C:\Users\sbdaki\Desktop\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\HashMyFiles\Sample Files - OK
	It calculates MD5, SHA1, CRC32
---
## Task 4: Perform File and Text Message Encryption using CryptoForge

	[Win 11]
	Install CryptoForge Z:\CEHv12 Module 20 Cryptography\Cryptography Tools\CryptoForge
	Z:\CEHv12 Module 20 Cryptography\Cryptography Tools\CryptoForge\Confidential.txt - Right click - Show more option - Encrypt -> The file gets encrypted.
	Share the file on shared drive
	
	[Win server 2019]
	Install CryptoForge Z:\CEHv12 Module 20 Cryptography\Cryptography Tools\CryptoForge
	Copy file from shared drive and decrypt it. See the contents of the file.
	---
	Encrypt message 
	
	[Win Server 2019]
	Launch Crytoforge Text -> Write content - This is my account no : 1234567890
	Click passphrase - Enter passphrase - OK
	Save the file sample.cfg and shared 
	
	[Win 11]
	Luanch Cryptoforge Text -> Open file sample.cfg and Decrypt - provide the same passphrase and see the decrypted content
---
## Task 5: Encrypt and Decrypt Data using BCTextEncoder

	[Win 11]
	Luanch BCTextEncoder - Content - This is sensitive information needs to be kept confidential. Encode with passcode - enter passcode and Encode
	Save file Desktop/bc_encoded - share file via shared drive
	
	[Win server 2019]
	Launch BCTextEncoder - Open file and Decode - Enter passphrase and contents are decrypted.
---
# Lab 2: Create a Self-signed Certificate
---
# Lab 3: Perform Email Encryption
---
# Lab 4: Perform Disk Encryption
## Task 1: Perform Disk Encryption using VeraCrypt
[Win 11]
Download VeraCrypt
Launch
Create Volume -> Create an encrypted file container (default option) -> Select File -> Desktop/MyVolume -> Save -> Next -> Volumne size: 5 MB -> Passphrase -> FileSystem FAT, Cluster Default, Select Checkbox [Random pool, Header key, master key] - Hover over the screen for 30 seconds -> Format -> OK -> Exit

	 VeraCrypt main window appears; select a drive (here, I:) and click Select File….Desktop/MyVolume -> Open -> Mount -> Password -> ok
	 VeraCrypt will mount the volume in I: drive
	
	 Create a file on Desktop/Sample with content - Move to I drive
	 Veracrypt -> Dismount -> Exit
	 The I: drive located in This PC disappears.
---
## Task 2: Perform Disk Encryption using BitLocker Drive Encryption
---
# Lab 5: Perform Cryptanalysis using Various Cryptanalysis Tools
## Task 1: Perform Cryptanalysis using CrypTool
	[Win 11]
	Launch Cryptool
	New -> Unnamed notepad - insert content - Encrypt/Decrypt(modern) -> RC2 -> Keep Key length (8 bits) -> Text field enter 05 Encrypt
	Note: The chosen hexadecimal character acts as a key that you must send to the intended user along with the encrypted file.
	RC encryption of Unnamed1 - Save 
	Share the file 
	
	[Win server 2019]
	Launch cryptool
	Open -> select file - Encrypt/Decrypt(modern) - RC2 -> enter 05 in text -> Decrypt -> Able to see the decrypted content
	----
encrypt the data using Triple DES encryption.
Follow same steps for Triple AES -- key test enter as combination of 12, eg 12 12 12..

---
## Task 2: Perform Cryptanalysis using AlphaPeeler
	[Win 11]
	Launch AlphaPeeler
	Create file with contents Desktop/sample.txt
	Professional Crypt - DES Crypto - Plain text file (sample.txt) - Cipher text file (share:confidential.txt) - passphrase - Encrypt DES-EDC(CBC)
	Check confidential.txt - its encrypted file
	
	[Win server 19]
	Launch Alphapeeler
	Open file confidential.txt
	Professional cyrpt- DES Crypo - plain text (Desktop/Result.txt) - Cipher text file (share:confidential.txt) - Pasphrase - Decrypt DES-EDC(CBC)
