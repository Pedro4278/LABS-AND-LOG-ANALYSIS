# PsExec Lateral Movement Log Analysis

## Summary
This analysis examines network logs revealing a lateral movement technique using PsExec over SMB, a common method employed by attackers post-compromise to execute remote commands across a network. The findings demonstrate expertise in network traffic analysis, threat identification, and mitigation strategies, aligning with cybersecurity best practices.

## Data Source
- **Log Type**: Network logs  
- **Tools Used**: Wireshark, NetworkMiner  
- **Suspect IP**: 10.0.0.130  
- **Involved Hosts**: MARKETING-PC, SALES-PC, HR-PC, ADMIN$  
- **Timestamp**: 07:42, 2023  
- **Anomalous Behavior**: SMB commands, PsExec activity  

![Wireshark](https://raw.githubusercontent.com/Pedro4278/Log-Analysis/main/wireshark.png)

![NetworkMiner](https://github.com/Pedro4278/Log-Analysis/blob/688792d836171fb427fc2ebfda421c4e74f10f53/NetworkMiner.png?raw=true)

### Sequence of Events (Packet Analysis)
1. **Frames 126–129**: Malicious activity begins with a TCP handshake and SMB negotiation.  
2. **Frames 130–133**: NTLM authentication occurs, establishing credentials.  
3. **Frames 134–135**: The attacker initiates lateral movement via a Tree Connect to IPC$, a prerequisite for administrative tasks.  
4. **Frames 136–137**: Interface query to gather network context.  
5. **Frames 138–143**: Access to ADMIN$ share, followed by file creation actions.  
6. **Frames 144–146**: Creation of `PSEXESVC.exe`, confirming PsExec execution.  

## Context

### PsExec and `PSEXESVC.exe`
`PSEXESVC.exe` is a temporary service binary used by PsExec, a legitimate Sysinternals tool for remote command execution. Attackers exploit it to create services on victim machines, enabling lateral movement during post-compromise phases.

### NTLM Authentication
NTLM is a legacy Microsoft authentication protocol using a challenge-response mechanism. Its lack of mutual authentication and weak cryptography makes it vulnerable to exploitation compared to modern protocols like Kerberos.

## Evidence
The following artifacts were extracted using NetworkMiner:

### Files Recovered:
- `PSEXESVC.exe`: Remote execution service binary.  
- `.key` files: Associated with PsExec operations.  

### Network Details:
- **Source IP**: 10.0.0.130  
- **Destination IP**: 10.0.0.131  
- **Protocol**: SMB2  

![NetworkMiner extracted files and metadata](https://github.com/Pedro4278/Log-Analysis/blob/688792d836171fb427fc2ebfda421c4e74f10f53/net1.png?raw=true)

## Analysis

- **NTLM Vulnerability**: The use of NTLM facilitated the exploit due to its lack of mutual authentication and weak cryptography, unlike newer protocols.  
- **Authentication and Privilege Escalation**: NTLM authentication from `10.0.0.130` using the `\ssales` account was immediately followed by access to administrative shares, indicating privileged operations.  
- **PsExec Confirmation**: The creation of `PSEXESVC.exe` confirms PsExec-driven remote code execution.  
- **Timing**: All actions occurred within a ~40ms window, suggesting automated exploitation.  
- **MITRE ATT&CK Alignment**: The sequence of SMB commands and `PSEXESVC.exe` creation aligns with T1021.002 (Remote Services: SMB/Windows Admin Shares).  

## Conclusion
This analysis provides strong evidence of lateral movement and remote code execution via PsExec over SMB, a technique commonly used in post-exploitation phases. The findings highlight the need for immediate investigation and mitigation to prevent further compromise.

## Recommendations
1. **Block SMB Traffic**: Restrict unnecessary SMB traffic.  
2. **Enforce Stronger Authentication**: Transition from NTLM to Kerberos to mitigate authentication vulnerabilities.  
3. **Monitor Administrative Shares**: Implement alerts for unauthorized access to `ADMIN$` or `IPC$` shares.  
4. **Investigate Suspect IP**: Conduct a forensic analysis of `10.0.0.130` to identify the attack source.  
5. **Enhance Detection**: Deploy intrusion detection systems (IDS) to flag PsExec-related anomalies.  

## Tools and Techniques
- **Wireshark**, **NetworkMiner**  
- **MITRE ATT&CK Framework**: Applied to contextualize the attack technique.  

## Next Steps
- Implement recommended mitigations and monitor their effectiveness.  
- Conduct a broader network audit to detect similar activities.
