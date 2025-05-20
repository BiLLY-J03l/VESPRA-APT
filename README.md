# ALYA
- An advanced malware prototype designed for Windows using C, win32 API and NT API.
- ALYA is inspired by Carbanak APT -> https://attack.mitre.org/software/S0030/
- ALYA showcases how a cracked software or a pirated game can compromise your whole system quietly and maintain a long-term presence on the system.
- It demonstrates sophisticated techniques for persistence, evasion, and payload execution, with a focus on implementing reverse shell, keylogging functionality, and LSASS memory dumping. The malware leverages low-level APIs, advanced obfuscation methods, and injection techniques to evade detection and maintain a persistent presence on the target system.

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

### 3- Obfuscated Reverse Shell:
  - Implements a reverse shell with advanced obfuscation techniques to evade detection.
  - Ensures NT/SYSTEM privileges for elevated access to the compromised system.
  - Establishes a secure connection to a remote server for command and control.

### 4- Keylogging Functionality:
  - Captures keystrokes from the target system using low-level APIs.
  - Exfiltrates captured data securely to the attacker's server.

### 5- Additional Functionality:
  - **LSASS Memory Dumping:** Dumps the memory of the Local Security Authority Subsystem Service (LSASS) to extract credentials.
  - **VNC Monitoring:** Allows remote monitoring and control of the target system.
  - **Backdoor Communication:** Establishes a persistent backdoor that connects to a malicious server on system boot.
  - **Adding Users:** Adds a user and adds it to the Administrators group.
  - **RDP functionality:** Enables RDP on the machine and configure the Windows Firewall accordingly.
  - All the code written in that repo is obfuscated either by offsets or string splitting, hence evading EDRs and AVs.

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

ALYA/

- **ALYA/**
  - **src/**                  
    - **stage_zero.c**        
    - **win_service32.c**     
    - **dll_injector.c**      
    - **legit.c**
    - **enc.c**
    - **app.manifest**
  - **installers/**
      - **setup.exe**
      - **tightVNC.msi**
  - **docs/**
      - **TightVNC_2.7_for_Windows_Installing_from_MSI_Packages.pdf**
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

- **src/ enc.c**
  - the encryption program I used to encrypt the files to be received and decrypted by stage_zero.exe.

- **src/ app.manifest**
  - the manifest file that prompts the victim for UAC and asks for admin privileges.
    
- **installers/ setup.exe**
  - the actual FitGirl-Repack crack without stage_zero.exe

- **installers/ tightvnc-setup.msi**
  - .msi installer for tightVNC
 
- **docs/ TightVNC_2.7_for_Windows_Installing_from_MSI_Packages.pdf**
  - tightVNC msi installer documentation that I used to install tightvnc-setup.msi package with the proper configurations and without any UI.

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
- Using WinRAR to create a .sfx archive with the correct configuration outputs another .exe file that contains setup.exe and stage_zero.exe
- The user will continue to setup the cracked game and stage_zero.exe would be done establishing a persistant foothold.
  
--------------------------------------------------------------------------------------------------------
## Execution Theory

### What Happens when the user clicks on setup.exe?
- Caves Of Qud game asks for admin privileges along with stage_zero.exe
- Once the user clicks ok, the game setup UI appears to begin the setup and stage_zero.exe starts executing in the background.

### What will stage_zero.exe do?
- the most important thing in stage_zero.exe is to include zero injections, shellcode executions or reverse shell connections or other techniques to communicate with the attacker.
- Consider it as if it's configuring the machine only.
- stage_zero.exe is only here to maintain access, modify registery keys, download, decrypt encrypted files from the adversary's HTTP server.
- it creates a hidden folder called "C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\" and downloads 4 xor-encrypted files and decrypt them in memory and store them to 4 hidden files:
  - win_service32.exe:
    - dumps lsass.exe to a .dmp file and sends it to the adversary's FTP server.
    - downloads and decrypts an encrypted shellcode and injects it into a process.
    - implements sockets to start a reverse connection to the adversary open port with SYSTEM privileges (Highest Ever Privilege).
  - legit.dll:
    - a dll file that is injected to a process and provides keylogging functionality and sends the .log file to the adversary's FTP server.
  - dll_injector.exe:
    - its purpose is to take legit.dll full path as an arg and injects it to a dummy process that it created, then exits.
  - tightVNC.msi:
    - a perfectly safe .msi installer that is executed with certain options to be installed without UI and with proper configuration.
- Then, stage_zero.exe creates a new user with a fairly convincing name, so that the user doesn't touch it or delete it.
- Then, it enables RDP through registery and service manipulation and configure windows firewall accordingly.
- Then, it insalls TightVNC with certain msi options to ensure its installation without any user interaction nor UI.
- Then, it furthur modifies the registery "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"and adds the dll_injector.exe with the legit.dll full path to achieve system-level keylogging persistance.
- This makes sure that if ANY user logs onto this machine the keylogger will keep logs of the keystrokes and sends it to the adversary's FTP server.
- Then, stage_zero.exe executes win_service32.exe which installs the service to the service control manager (SCM) database, with automatic startup to ensure that the service starts up with system bootup.
- It then, starts the service explicitly. (You can delete that anyway).
- **(OPTIONAL)** It can also disable Windows Defender through registery manipulation which I don't recommend as it can become **VERY NOISY** to the user if he/she casually went to open up Defender Settings.

### What happens after Stage 0 (upon restart)?
#### win_service32.exe

#### dll_injector.exe legit.dll
