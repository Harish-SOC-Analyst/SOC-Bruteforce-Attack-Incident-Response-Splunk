# SOC-Bruteforce-Attack-Incident-Response-Splunk
Brute-force attack detection and incident response using Splunk SIEM (EventCode 4625) with correlation rule and investigation workflow.

1. Title

SMB Brute Force Attack Detection using Splunk SIEM (EventCode 4625)

2. Objective

Detect and investigate brute-force authentication attempts against SMB service using Splunk correlation rules.

3. Lab Setup 
Kali Linux VM (attacker) 
Windows VM with UF (target SMB 445) 
Main Host (SIEM server Splunk)

4. Incident Summary

Attack Type: Brute Force
Target Protocol: SMB (TCP 445), Logon_Type - 3
Event Code: 4625
Failed Attempts: 150+
Peak Rate: 50/min
Source IP: 192.168.56.102 (Attacker kali vm)
Target IP: Not explicitly available
Target Name : DESKTOP-973UF43
Target User: Harsh
No successful login observed (no 4624)

5. Detection Logic (SPL)

index=* EventCode=4625
| bin _time span=1m
| stats count by _time src_ip
| where count > 49
 
 (Detects brute-force attempts exceeding 49 failed logins per minute.)

6. Triage

Confirmed repeated authentication failures
Verified internal attacker source
Validated no successful login
Classified as brute-force activity

“The brute-force alert was triaged and classified as a medium-severity incident based on repeated authentication failures (EventCode 4625) from a single source IP within a short time window.”

7. MITRE ATT&CK

T1110 – Brute Force

9. Conclusion -
    Incident successfully detected and validated using Splunk SIEM correlation rule. No evidence of credential compromise observed.
