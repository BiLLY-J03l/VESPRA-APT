# ALYA
ALYA is an advanced malware prototype designed for educational and research purposes.

-It demonstrates sophisticated techniques for persistence, evasion, and payload execution, with a focus on implementing an obfuscated reverse shell, keylogging functionality, and LSASS memory dumping. The malware leverages low-level APIs, advanced obfuscation methods, and injection techniques to evade detection and maintain a persistent presence on the target system.

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

