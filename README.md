# ALYA
ALYA is an advanced malware prototype designed for educational and research purposes.

-It demonstrates sophisticated techniques for persistence, evasion, and payload execution, with a focus on implementing an obfuscated reverse shell, keylogging functionality, and LSASS memory dumping. The malware leverages low-level APIs, advanced obfuscation methods, and injection techniques to evade detection and maintain a persistent presence on the target system.

**Disclaimer:** This project is intended solely for educational and research purposes. It must not be used for any malicious activities. I am NOT responsible for any misuse of this software.
---------------------------------------------------------------------------------------------------------------------------------

## Ethical Considerations

- This project is strictly for educational and research purposes. It is designed to help cybersecurity professionals and researchers understand advanced malware techniques and develop effective countermeasures. The following ethical guidelines must be followed:
  
    - Controlled Environment: The malware must only be tested in a virtualized environment with no external network access.
    - No Malicious Use: The software must not be used to harm or compromise any system without explicit permission.
    - Compliance with Laws: Ensure compliance with all applicable laws and regulations in your jurisdiction.


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

--------------------------------------------------------------------------------------------------------

## Development Environment

- **The following tools and technologies were used in the development of this project:**

  - Virtualization: VirtualBox/VMware for testing in a controlled environment.
  - Process Analysis: Process Hacker 2 for analyzing and debugging processes.
  - Network Analysis: Wireshark for monitoring network traffic.
  - Programming Language: C/C++ for low-level API usage and performance.
  - Obfuscation Tools: Custom XOR encryption and other obfuscation techniques.
  
-----------------------------------------------------------------------------------------------------

## Project Structure

ALYA/

- **ALYA/**
  - **src/**                  # Source code for the malware prototype
    - **persistence/**        # Code for persistence mechanisms
    - **evasion/**            # Code for evasion techniques
    - **reverse_shell/**      # Code for obfuscated reverse shell
    - **keylogger/**          # Code for keylogging functionality
    - **lsass_dump/**         # Code for LSASS memory dumping
  - **docs/**                 # Documentation and research materials
  - **tests/**                # Test scripts and virtual machine setups
  - **README.md**             # This file


--------------------------------------------------------------------------------------------------------
## Development Methodology

- Since I understood most of the techniques used in malware, the most important thing I wanted to achieve was escalating my privileges.
- I kept looking for potential bugs in the latest Windows and couldn't find anything recent.
- I had two options, either find a zero-day in Windows, or use Social Engineering.
- When does a user let a program use admin privileges explicitely (UAC)? Program Setups!
- So my delivery method are crack softwares that users install all the time such as pirated games, cracked Office... etc.
- I chose a small-sized cracked game from FitGirl-Repacks called "Caves of Qud". You can use any other .exe file to do that.
- Via social engineering, I have successfully bypassed UAC and escalated my privileges.
- The tricky thing here is once the user clicks on setup.exe and grants admin privileges, it also grants them to my stage_zero.exe.
- Using WinRAR to create a .sfx archive with the correct configuration outputs another .exe file that contains setup.exe and stage_zero.exe
- The user will continue to setup the cracked game and stage_zero.exe would be done establishing a persistant foothold.


