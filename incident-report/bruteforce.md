🛡️ Incident Report: SMB Brute Force Attack Detection
1. Incident Overview

A brute-force authentication attack was detected targeting a Windows endpoint over SMB (TCP 445). The activity was identified through repeated failed login attempts (EventCode: 4625) observed in Splunk SIEM logs.

The attack originated from an internal lab system and generated multiple high-frequency authentication failure bursts.

2. Affected Asset
Target Host: DESKTOP-973UF43 (Windows VM)
Service: SMB (TCP 445)
Log Source: Windows Security Logs
Event Type: EventCode 4625 (Failed Logon Attempts)

3. Timeline of Events (Aggregated View)
Based on Splunk time-binned analysis:

Timestamp (UTC)	       src_ip 	      Failed Attempts
2026-06-05 23:21:00 	192.168.56.102	  50
2026-06-05 23:24:00	  192.168.56.102  	50
2026-06-06 02:00:00 	192.168.56.102	  50

Observations:
Repeated spikes of 50 failed authentication attempts per minute
Activity is periodic, indicating automated attack behavior
No successful authentication events (EventCode 4624) observed during the timeframe

4. Triage Analysis

Severity Classification: Medium

Reasoning:
High-frequency authentication failures within short time intervals
Consistent repeated attempts against a single target system
Behavior is indicative of brute-force attack pattern
SOC Decision:
Alert classified as brute-force authentication attack
Escalation not required beyond lab simulation scope
Incident marked for investigation and documentation

5. Attack Behavior Analysis
Attack Type: Brute Force (Credential Guessing)
Pattern: Repeated login attempts in bursts
Target Scope: Single host (DESKTOP-973UF43)
Automation: Likely scripted (constant 50 attempts per interval)
Protocol: SMB authentication over TCP 445

6. Detection Logic

The detection was performed using a Splunk correlation search:

index=* EventCode=4625
| bin _time span=1m
| stats count by _time src_ip
| where count > 49
Logic Explanation:

This rule aggregates failed login attempts in 1-minute intervals and triggers an alert when the count exceeds 49 events from a single source.

7. Findings
Total observed failed login bursts: 3
Peak attempt rate: 50 attempts per minute
Target system remained uncompromised
No successful authentication detected

8. Impact Assessment
Confidentiality: Not compromised
Integrity: Not impacted
Availability: Not affected

No evidence of successful intrusion was observed. The attack remained at the authentication failure stage.

9. MITRE ATT&CK Mapping
Technique: T1110 – Brute Force

10. Recommendations
Even in a production environment, the following controls are recommended:

Implement account lockout policies after repeated failed attempts
Enable multi-factor authentication (MFA)
Monitor SMB authentication anomalies in real time
Restrict SMB access to trusted hosts only
Deploy rate-based alerting for authentication failures

11. Conclusion
The observed activity represents a successful detection of a brute-force authentication attempt against a Windows SMB service. Splunk correlation rules effectively identified repeated failed login attempts, enabling timely triage and classification of the event as a security incident.
