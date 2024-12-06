# Incident Report
> Event ID: 234
> 
> Rule Name: SOC176 - RDP Brute Force Detected
## Alert
Based on the information that the alert provided, it appears that there are suspicious
login failure events detected on a host named **Matthew** with an IP address of
`172.16.17.148`. The Alert is triggered by the **SOC176** rule for **RDP Brute Force
Detected**.

![image](https://github.com/user-attachments/assets/a663e146-9cbe-4ea2-acc9-1e6f3db31811)

The alert suggests that there were login attempts from the source IP address
`218.92.0.56` to the destination host named **Matthew** `172.16.17.148` over RDP. The
firewall allowed this traffic. However, the attempts triggered an alert due to repeated
login failures from the same source, indicating attempts to access non-existing
accounts.This activity was flagged as the detection of multiple login failures from a single source, leading to the triggering of an alert. This behavior could be indicative of a potential
brute force attack and needs to be investigated.

----

## Task List
- [ ] Take Ownership
- [ ] Create Case
- [ ] Utilise Playbook
- [ ] Investigate and Document Findings
- [ ] Determine True/False Positive
- [ ] Close Alert

----

## Detection
### Enrichment & Context
As the playbook suggests we can start investigating the alert by verifying that the IP
address is  **internal** or **external**.

![image](https://github.com/user-attachments/assets/792a88f5-0938-44cb-be7c-89f6f92d14ea)

> [!TIP]
> - Source IP Address: `218.92.0.56`
> - Destination IP Address: `172.16.17.148` **Matthew**

As seen in the alert details, source IP address `218.92.0.56` is **external**.

----

### IP Reputation Check
The second step of the playbook recommends performing an IP reputation check of the
attacker's IP address via recommended resources susch as VirusTotal, AbuseIPDB, and LetsDefend TI.

![image](https://github.com/user-attachments/assets/a0fa56aa-1334-42cf-9d5d-7030b7712d75)

Based on the information provided by VirusTotal, the IP address `218.92.0.56` originating from China
has been flagged as malicious by 14 antivirus engines.

![image](https://github.com/user-attachments/assets/deb1fb41-9b5d-4c20-bde0-910498769100)

On the LetsDefend threat intel tab, upon cross-referencing the source IP address mentioned, it was determined that the address had been categorized as malicious.

![image](https://github.com/user-attachments/assets/204d9ba5-8e1c-4ebe-bad6-e79c04de9777)

By cross-referencing the IP address with Abuseip the IP address was discovered to be  malicious and reported many times espcially in categories `ssh` and `brute-force`.

![image](https://github.com/user-attachments/assets/cdfe20ec-ad3d-4af4-9fbc-c5b410789d2b)

Thus, the answer to the playbook is **Yes**, the attacker IP is indeed suspicious.

---- 

## Analysis
### Traffic Analysis
The third step of the playbook involves traffic analysis. Specifically, it suggests
searching for the attacker's IP address within the log management system. From there,
it's important to determine if there have been any requests to the server's
SSH/RDP/VPN ports originating from the attacker's IP address.

![image](https://github.com/user-attachments/assets/06a70496-ad82-44da-853b-0066f20b3259)

There are 15 firewall logs recorded from the IP address `218.92.0.56` attempting to
connect to the host named **Matthew** at IP address `172.16.17.148`. These logs
specifically detail attempts to access `port 3389`, commonly used for `Remote Desktop
Protocol (RDP) connections`.

![image](https://github.com/user-attachments/assets/e7906127-e216-491c-97d7-8da3e1a86827)

The answer to the playbook is **Yes**, there are multiple requests from the Attacker IP address to the target server's SSH or RDP port.

![image](https://github.com/user-attachments/assets/103978be-7fed-4bbc-b353-eec13ad0a785)


----

### Determine the Scope

The next step in the playbook involves investigating whether the attacker's IP address
has attempted to establish SSH/RDP connections with multiple servers or clients as the
target. This step aims to determine if the attack is targeted toward a single specific
server or if multiple servers or clients are being targeted simultaneously.

![image](https://github.com/user-attachments/assets/57fdf941-ff10-4d7d-9539-834f557b0162)

The answer is **No**, only one client is targeted. Upon inspecting the log management
and filtering for the attacker's source address, it reveals only one destination IP address,
which is `172.16.17.148`, corresponding to the host named **Matthew**.

![image](https://github.com/user-attachments/assets/bc8fb50c-0ce5-4237-be63-5db12f1af43e)

----

### Log Management
To determine if the brute force attack was successful, we need to analyze the SSH/RDP
audit logs. Here's how to do it for both Windows and Linux systems:
For Windows:
- Look for Event ID `4624`, which indicates a successful login.
- Also, examine Event ID `4625`, which signifies a failed login attempt.

If successful logins are recorded after multiple failed login attempts from the same
source address to the same target, it indicates that the brute force attack was
successful.

![image](https://github.com/user-attachments/assets/a421e83c-e035-430b-a4a1-8d77f9026c1d)

At the log management tab, I found that on March 7, 2024, at 11:44 AM, several failed logon events were observed.
- Several failed logon events observed
- Usernames attempted: `sysadmin`, `admin`, `guest`
- Event ID: `4625` (An account failed to log on)
- Error Code: 0xC000006D (Unknown user name or bad password)

![image](https://github.com/user-attachments/assets/0749fe3a-f4c1-48bb-ba89-8b060a1dc54c)

These failed logon attempts indicate potential unauthorized access attempts or a brute force attack targeting the system. The use of generic usernames like `sysadmin`, `admin`, and `guest` suggests an attempt to exploit common account names. Following numerous failed logon attempts, the attacker successfully accessed the host using the username **Matthew** at Mar, 07, 2024, 11:44 AM.

![image](https://github.com/user-attachments/assets/fbdcac57-5dd8-4ea8-b0fe-6a0990107045)

![image](https://github.com/user-attachments/assets/4bb1c3f5-5a1f-4d69-94bb-c9e5d991b839)

After the successful logon, the attacker executed the following commands on the host.
- Command: "C:\Windows\system32\cmd.exe"
- Command: whoami (`Mar 7 2024 11:45:51`, Process ID: `5360`)
- Command: net user letsdefend (`Mar 7 2024 11:45:58`, Process ID: `5360`)
- Command: net localgroup administrators (`Mar 7 2024 11:46:34`, Process ID: `5360`)
- Command: netstat -ano (`Mar 7 2024 11:46:53`, Process ID: `5360`)

These commands indicate the attacker's attempt to gain information about the system, users, and network connections, potentially for further malicious activities.

![image](https://github.com/user-attachments/assets/0bb0a7ed-5866-42cb-a206-00fb574b67b2)


----

## Containment
### Should the Device be Isolated
The step is to determine if the device require isolation. 

![image](https://github.com/user-attachments/assets/af202195-c312-4689-ad65-2c2b581575a1)

Based on the information gathered during the investigation, it is highly likely that the system has been compromised. To prevent further data loss or unauthorized access, it is recommended to isolate the system from the network immediately. The answer to the playbook is **Yes**.

Isolation of the host can be made from the endpoint security tab.

> Hostname: Matthew
>
> IP Address: 172.16.17.148

![image](https://github.com/user-attachments/assets/179e63d5-468d-4e37-8cff-24ee045a626e)

----

## Lesson Learned
- Effective monitoring and alerting systems are essential for detecting and responding to suspicious activities promptly.
- Monitoring for specific indicators of compromise (IOCs) helps detect potential security threats, but they should be supplemented with in-depth analysis.
- Rapid response to security incidents is critical for minimizing the impact of cyber
threats.
- Educating users and administrators about common attack vectors, such as brute force attacks, helps mitigate risks associated with unauthorized access attempts.
- Enabling and collecting logs from operating systems can significantly enhance visibility into your network's security posture.

----

## Remediation Actions
- Enforce strong password policies, including the use of complex passwords and regular password changes, to mitigate the risk of brute force attacks. Consider implementing multi-factor authentication (MFA) for an added layer of security.
- Restrict external network access to Matthew and Server instances accessible via the public internet, until the necessary upgrades can be performed
- Set up a VPN solution to provide secure remote access to the network. VPNs encrypt data transmitted between remote devices and the network, reducing the risk of interception or unauthorized access.
- Isolate the compromised machine from the network to prevent the attacker from accessing other resources and systems within the organization.

----

## Summary
The alert report highlights the detection of a suspicious web attack targeting the host named Matthew (IP: `172.16.17.148`). The attack was triggered by the SOC176 - RDP Brute Force Detected rule, indicating a potential vulnerability that threat actors exploit to gain unauthorized access to machines via RDP (Remote Desktop Protocol).<br>

The report outlines a series of suspicious activities targeting a host named "Matthew" with the IP address `172.16.17.148`. The incident was triggered by the SOC176 rule for RDP Brute Force Detection, highlighting repeated login failures from the external source IP address `218.92.0.56`.<br>

Upon investigation, it was discovered that the source IP address had a malicious reputation according to multiple threat intelligence platforms, indicating potential security risks. Additionally, 15 firewall logs recorded attempts to connect to the host "Matthew" over RDP, suggesting a concerted effort to gain unauthorized access.<br>

Despite failed login attempts, the attacker successfully logged in using the username "Matthew." Subsequent analysis revealed a series of command executions, including attempts to gather system information and escalate privileges.

----

## MITRE ATT&CK
| MITRE Tactics   | MITRE Techniques |
| ------------- | ------------- |
| Initial Access  | Valid Accounts: T1078, T1078.003 |
| Discovery | Account Discovery: T1087, T1087.001 |
| Execution  | Command and Scripting Interpreter: T1059, T1059.003  |
| Credential Access  | Brute Force: T1110, T1110.001  |

----

## Artifacts
| IOC Type   | Comment | Value |
| ------------- | ------------- | ------------- |
| IP Address  | Attacker IP | `218.92.0.56`|
| IP Address  | Victim IP | `172.16.171.148`|
| Username  | Abused username | admin |
| Username  | Abused username  | guest |
| Username  | Abused username  | sysadmin |
| User  | Victim  | Matthew |

----

## Analysis Note
> - `218.92.0.56` (Source IP: Malicious)
> - The IP was flagged by 14 AV engines as malicious (VirusTotal)
> - The IP was reported 458,120 times for malicious activities such as port scans, and brute force attacks via SSH (AbuseIPDB)
> - Origin: Shanghai, China (AbuseIPDB)
> - Usage Type: Fixed Line ISP (AbuseIPDB)
> - Domain Name: chinatelecom.cn (AbuseIPDB)
> - LetsDefend Threat Intel reported `218.92.0.56` as malicious on `Mar, 08, 2024, 02:33 PM`





