# VESPRA
- An advanced malware prototype designed for Windows using C, win32 API and NT API.
- VESPRA is inspired by Carbanak APT -> https://attack.mitre.org/software/S0030/
- VESPRA showcases how a cracked software or a pirated game can compromise your whole system quietly and maintain a long-term presence on the system.
- It demonstrates sophisticated techniques for persistence, evasion, and payload execution, with a focus on implementing reverse shell, keylogging functionality, and evasive LSASS memory dumping. The malware leverages low-level APIs, advanced obfuscation methods, and injection techniques to evade detection and maintain a persistent presence on the target system.

**Disclaimer:** This project is intended solely for educational and research purposes. It must not be used for any malicious activities. I am NOT responsible for any misuse of this software.

---------------------------------------------------------------------------------------------------------------------------------
## Features

### 1- Persistence Mechanisms:
  - Utilizes low-level techniques and the undocumented Native API to achieve persistence.
  - Implements registry modifications and service creation to ensure the malware runs across system reboots.

### 2- Evasion Techniques:
  - Employs XOR decryption for payload obfuscation.
  - Avoids high-level API calls to reduce detection by antivirus software.
  - Uses advanced injection methods, such as process and DLL injection, to execute malicious code within legitimate processes.
  - Evasively dumps the memory of the Local Security Authority Subsystem Service (LSASS) to extract credentials and send them securely via FTP over TLS/SSL.
  - Employs low-level **Anti-Debugging** methods to check if a debugger is present.
  - Employs **Anti-VM** techniques that check for VM presence and evade sandbox analysis.
  - Employs **Anti-Disassembly** techniques using standard C math operations to obfuscate the main graph flow.

### 3- Obfuscation Techniques:
  - Implements a reverse shell with advanced obfuscation techniques to evade detection.
    - This reverse shell NT/SYSTEM privileges for elevated access to the compromised system.
    - It Establishes a secure connection to a remote server for command and control.
  - Implements string splitting that constructs strings only in runtime, avoiding static analysis.
  - Implements offset obfuscation that is used to for the functions to hinder the analysis of the malware.
    
### 4- Keylogging Functionality:
  - Captures keystrokes from the target system using low-level APIs.
  - Exfiltrates captured data securely to the attacker's server using FTP over TLS/SSL.

### 5- Monitoring Functionality:
  - **VNC Monitoring:** Allows remote monitoring and control of the target system.
  - **RDP functionality:** Enables RDP on the machine and configure the Windows Firewall accordingly.
  - **WinRM Monitoring:** Establishes WinRM access, so adversary can utilize evil-winrm in post-exploitation phase.
  - **Adding Users:** Creates a user and adds it to the Administrators group.
  - **Backdoor Communication:** Establishes a persistent backdoor that connects to a malicious server on system boot.
--------------------------------------------------------------------------------------------------------

## Development Environment

- **The following tools and technologies were used in the development of this project:**

  - Virtualization: VirtualBox/VMware for testing in a controlled environment.
  - Process Analysis: Process Hacker 2 for analyzing and debugging processes.
  - Network Analysis: Wireshark for monitoring network traffic.
  - Programming Language: C for low-level API usage and performance.
  - Obfuscation Tools: Custom XOR encryption and other obfuscation techniques.
  
-----------------------------------------------------------------------------------------------------

## Project Structure

VESPRA/

- **VESPRA/**
  - **src/**                  
    - **stage_zero.c**        
    - **win_service32.c**     
    - **dll_injector.c**      
    - **legit.c**
    - **app.manifest**
  - **installers/**
      - **setup.exe**
      - **tightVNC.msi**
  - **docs/**
      - **TightVNC_2.7_for_Windows_Installing_from_MSI_Packages.pdf**
  - **utils/**
      - **file_enc.c**
      - **shellcode_enc.c**
      - **string_splitting.c**
      - **offset.c**
      - **download_prototype.c**
  - **README.md**             

### Description

- **src/ stage_zero.c**
  - It downloads XOR-encrypted files from the malicious HTTP server and decrypts them in memory and store them to hidden files inside a hidden folder.
  - It modifies the registery hive (HKEY_LOCAL_MACHINE) and adds the "dll_injector.exe /path/to/legit.dll" to execute it everytime ANY user logs into the machine. (System-Level Persistence)
  - It starts a process to run win_service32.exe and installs the service on the victim machine. (NOT START)
  - It install tight_vnc.msi with certain msi properties to ensure proper configuration without any UI.
  - It starts the malicious service. (if not executed, the service will be executed by next startup)
  - It modifies the registery hive to disable Windows Defender. (can be noisy, if user had to check Defender in Windows Settings)

- **src/ win_service32.c**
  - I took the service template from Microsoft Docs https://learn.microsoft.com/en-us/windows/win32/services/svc-cpp
  - It required some tweaking to port the code into C, and more tweaking to dump lsass.exe, send the file to my FTP server and start a reverse shell.
  - Then it starts a reverse connection to the adversary with "NT AUTHORITY\SYSTEM" privileges.

- **src/ dll_injector.c**
  - It takes the full path of legit.dll as an arg.
  - It creates a cmd.exe process with as a hidden window.
  - It uses NT API to load the legit.dll to the cmd.exe process.
  
- **src/ legit.c**
  - a DLL that once loaded into a process's address space, logs keystrokes written by the user to a .log file and sends the file to the adversary's FTP server, periodically.

- **src/ app.manifest**
  - the manifest file that prompts the victim for UAC and asks for admin privileges.
    
- **installers/ setup.exe**
  - the actual FitGirl-Repack crack without stage_zero.exe

- **installers/ tightvnc-setup.msi**
  - .msi installer for tightVNC
 
- **docs/ TightVNC_2.7_for_Windows_Installing_from_MSI_Packages.pdf**
  - tightVNC msi installer documentation that I used to install tightvnc-setup.msi package with the proper configurations and without any UI.
 
- **utils/ file_enc.c**
  - the encryption program I used to encrypt the files to be received and decrypted by stage_zero.exe.

- **utils/ shellcode_enc.c**
  - the encryption program I used to encrypt the shellcode file to be received, decrypted and injected by win_service32.exe.
 
- **utils/ offset.c**
  - the offset program I used to get the offsets of the functions I used across the APT.

- **utils/ string_splitting.c**
  - the string splitting program I used to get the split the strings and test their validity before I added them across the APT.
 
- **utils/ download_prototype.c**
  - a downloader program I tested before adding to the main APT logic.
--------------------------------------------------------------------------------------------------------
## Development Methodology

- Since I understood some of the techniques used in malware, the most important thing I had to achieve was escalating my privileges.
- I kept looking for potential bugs in the latest Windows Versions and couldn't find anything relatively simple to exploit.
- I had two options, either find a zero-day in Windows, or use Social Engineering.
- When does a user let a program use admin privileges explicitely (UAC)? Program Setups!
- So my delivery method are crack softwares that users install all the time such as pirated games, cracked Office... etc.
- I chose a small-sized cracked game from FitGirl-Repacks called "Caves of Qud". You can use any other .exe file to do that.
- Via social engineering, I have successfully bypassed UAC and escalated my privileges.
- Now, once the user clicks on setup.exe and grants admin privileges, it also grants them to my stage_zero.exe.
- Using WinRAR to create a .sfx archive, with the correct configuration, outputs another .exe file that contains setup.exe and stage_zero.exe
- The user will continue to setup the cracked game and stage_zero.exe would be done establishing a persistant foothold.
  
--------------------------------------------------------------------------------------------------------
## Execution Theory

### What Happens when the user clicks on setup.exe?
- Caves Of Qud game asks for admin privileges via UAC along with stage_zero.exe
- Once the user clicks ok, the game setup UI appears to begin the setup and stage_zero.exe starts executing in the background.

### What will stage_zero.exe do?
- the most important thing in stage_zero.exe is to include very little, if not any, injections, shellcode executions or reverse shell connections or other techniques to communicate with the attacker.
- Consider it as if it's configuring the machine only.
- stage_zero.exe is only here to configure the machine, modify registery keys, download, decrypt encrypted files from the adversary's HTTP server.
- it creates a hidden folder called "C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\" and downloads 4 xor-encrypted files and decrypt them in memory and store them to 4 files:
  - **win_service32.exe:**
    - dumps lsass.exe evasively
    - downloads and decrypts an encrypted MSF shellcode and injects it into a process.
    - implements sockets to start a reverse connection to the adversary open port with SYSTEM privileges (Highest Privilege Possible).
  - **legit.dll:**
    - a dll file that is injected to a process and provides keylogging functionality and sends the .log file to the adversary's FTP server.
  - **dll_injector.exe:**
    - its purpose is to take legit.dll full path as an arg and injects it to a dummy process that it created, then exits.
  - **tightVNC.msi:**
    - a perfectly safe .msi installer that is executed with certain options to be installed without UI and with proper configuration.
- Then, stage_zero.exe creates a new user with a fairly convincing name, so that the user doesn't touch it or delete it.
- Then, it enables RDP through registery and service manipulation and configure windows firewall accordingly.
- Then, it installs TightVNC with certain msi options to ensure its installation without any user interaction nor UI.
- Then, it enables WinRM, so the adversary can use evil-winrm for further post-exploitation.
- Then, it furthur modifies the registery "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"and adds the dll_injector.exe with the legit.dll full path to achieve system-level keylogging persistance.
- This makes sure that if ANY user logs onto this machine the keylogger will keep logs of the keystrokes and sends it to the adversary's FTP server.
- Then, stage_zero.exe executes win_service32.exe which installs the service to the service control manager (SCM) database, with automatic startup to ensure that the service starts up with system bootup.
- It then, starts the service explicitly. (It was used for debugging, You should disable that as it's configured to run on autostart).
- **(OPTIONAL)** It can also disable Windows Defender through registery manipulation which I don't recommend as it can become **VERY NOISY** to the user if he/she casually went to open up Defender Settings.
- <img width="1042" height="399" alt="image" src="https://github.com/user-attachments/assets/366f0e58-9d89-4f8b-a1f5-cd92fdbe31d1" />

### What happens after Stage 0 (upon restart)?
#### win_service32.exe:
- The malicious service executes on startup.

- It opens a handle to a file called fawf3na.chkf in this path C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\fawf3na.chkf.
  - If the file exists, it proceeds to skip the lsass dumping part and starts from point **4.**.
  - If the file doesn't exist, it creates that file and continues to point **3.**.
  - WHY? Lsass dumping, on windows 11, doesn't work with mere Admin privileges, and only with NT AUTHORITY ones, so I proceeded to add that simple logic to dump lsass.exe and send it via FTP only once, making the service more e as it interacts with lsass.exe only once.

- It clones lsass.exe memory and dumps that clone to a .dmp file to this path C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\dumpfile.dmp.
  - Then it puts this file via FTPS on the adversary's FTP server.
  - Even if the analyst monitored the network traffic, they won't be able to know the credentials of the FTP server or the contents of the .dmp file.
  - The .dmp file then can be later inspected by mimikatz and the adversary can crack the hashes offline.
- It, then, deletes the .dmp file from the folder and continues the execution.
- <img width="1121" height="362" alt="image" src="https://github.com/user-attachments/assets/ec475a26-3f88-4491-8109-b8b87aa3dbc5" />


- It downloads XOR-encrypted msf shellcode and keeps it in memory.
  - It spawns a cmd.exe process in the machine.
  - It decrypts the XOR-encrypted shellcode in memory then allocates and writes it in the address space of the spawned cmd.exe proceess.
  - Then, it executes the shellcode in the context of that remote process.
- <img width="1081" height="281" alt="image" src="https://github.com/user-attachments/assets/1ac211bf-2644-4ba0-bcee-17bad4d67508" />

- It uses a hand-written implementation of reverse shell using Winsock and socket programming.
  - It keeps connecting to the adversary's listening port ensuring SYSTEM privileges.
  - Even if some network issue occurs and the connection crashes, the service keeps trying to connect to the adversary.
- <img width="997" height="201" alt="image" src="https://github.com/user-attachments/assets/07792ab4-6abd-439d-a366-1179d300a87b" />


#### dll_injector.exe legit.dll:
- dll_injector.exe spawns cmd.exe process and uses a basic DLL injection method to make that spawned process load legit.dll into its address space.

- legit.dll:
  - it creates a mutex to prevent it from running too many instances, in case of multiple logins.
  - it logs the keystrokes typed by the victim and into a .log file to this path C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\log.log.
  - Then it puts this file via FTPS on the adversary's FTP server.
  - Even if the analyst monitored the network traffic, they won't be able to know the credentials of the FTP server or the contents of the log file.
  - The log file then can be later inspected by the adversary and search for sensitive data.
--------------------------------------------------------------------------------------------------------
## VirusTotal and Cuckoo Sandbox Analysis:
- **stage_zero.exe:**
  - <img width="1455" height="867" alt="image" src="https://github.com/user-attachments/assets/410eb8e2-26ca-43f0-91d7-f71e7fe8358b" />
  - <img width="1919" height="892" alt="image" src="https://github.com/user-attachments/assets/8547ddc3-f16f-4594-8e2e-aff7ce63d455" />

- **win_service32.exe:**
  - <img width="1919" height="915" alt="image" src="https://github.com/user-attachments/assets/91fb2a12-304f-493a-872c-f0d163a5b554" />
  - <img width="1919" height="911" alt="image" src="https://github.com/user-attachments/assets/fa8c4037-ef4c-4ebd-8e0b-7601d8431f9b" />

- **dll_injector.exe:**
  - <img width="1521" height="846" alt="image" src="https://github.com/user-attachments/assets/daf993e4-71f6-44c3-a6c0-73cd4eef3aeb" />
  - <img width="1919" height="883" alt="image" src="https://github.com/user-attachments/assets/3858485e-3c77-49bd-b563-e0f7beb3f53c" />

- **legit.dll:**
  - <img width="1918" height="918" alt="image" src="https://github.com/user-attachments/assets/afc68177-f56a-47b4-91b2-4739ef1f9b70" />
  - <img width="1915" height="905" alt="image" src="https://github.com/user-attachments/assets/8c35babe-0b86-4a6c-98a1-759a68ed82b3" />





