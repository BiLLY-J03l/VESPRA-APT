# ALYA
- ALYA is an advanced malware prototype designed for Windows using C, win32 API, NT API and advancd obfuscation methods.

- It demonstrates sophisticated techniques for persistence, evasion, and payload execution, with a focus on implementing an obfuscated reverse shell, keylogging functionality, and LSASS memory dumping. The malware leverages low-level APIs, advanced obfuscation methods, and injection techniques to evade detection and maintain a persistent presence on the target system.

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
  - All the code written in that repo is obfuscated either by offsets or string splitting, hence evading EDRs and AVs

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
  - **README.md**             

### Description

- **stage_zero.c**
  - It downloads XOR-encrypted files from the malicious HTTP server and decrypts them in memory and store them to hidden files inside a hidden folder.
  - It modifies the registery hive (HKEY_LOCAL_MACHINE) and adds the "dll_injector.exe /path/to/legit.dll" to execute it everytime ANY user logs into the machine. (System-Level Persistence)
  - It starts a process to run win_service32.c to install the service on the victim machine. (NOT START)
  - It install tight_vnc.msi with certain msi properties to ensure proper configuration without any UI.
  - It starts the malicious service. (if not executed, the service will be executed by next startup)
  - It modifies the registery hive to disable Windows Defender (can be noisy, if user had to check Defender in Windows Settings)

- **win_service32.c**
  - I took the service template from Microsoft Docs https://learn.microsoft.com/en-us/windows/win32/services/svc-cpp
  - It required some tweaking to dump lsass.exe and send the file to my ftp server.
  - Then it start a reverse connection to the adversary with "NT AUTHORITY\SYSTEM" privileges.

- **dll_injector.c**
  - It takes the full path of legit.dll as an arg.
  - It creates a cmd.exe process with hidden windows.
  - It uses NT API to load the legit.dll to the cmd.exe process.
  

- **legit.c**
  - a DLL that once loaded into a process's address space, logs keystrokes written by the user to a .log file and sends the file to the adversary's FTP server, periodically.


--------------------------------------------------------------------------------------------------------
## Development Methodology

- Since I understood most of the techniques used in malware, the most important thing I had to achieve was escalating my privileges.
- I kept looking for potential bugs in the latest Windows and couldn't find anything recent.
- I had two options, either find a zero-day in Windows, or use Social Engineering.
- When does a user let a program use admin privileges explicitely (UAC)? Program Setups!
- So my delivery method are crack softwares that users install all the time such as pirated games, cracked Office... etc.
- I chose a small-sized cracked game from FitGirl-Repacks called "Caves of Qud". You can use any other .exe file to do that.
- Via social engineering, I have successfully bypassed UAC and escalated my privileges.
- The tricky thing here is once the user clicks on setup.exe and grants admin privileges, it also grants them to my stage_zero.exe.
- Using WinRAR to create a .sfx archive with the correct configuration outputs another .exe file that contains setup.exe and stage_zero.exe
- The user will continue to setup the cracked game and stage_zero.exe would be done establishing a persistant foothold.

### What Happens when the user clicks on setup.exe?

- 


