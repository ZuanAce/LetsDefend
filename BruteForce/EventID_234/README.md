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

The answer to the playbook is **No**, there is no request from the Attacker IP address to the target server's SSH or RDP port but multiple requests to the target client's SSH or RDP port.

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

The answer to the 3rd part of the playbook is: **Delivered**, the email was allowed and delivered to the user.

----

### Delete Email From Recipient!
The 4th step is to delete the email from recipient as the playbook requested.

![image](https://github.com/user-attachments/assets/874c0619-8d99-41af-b2bd-54bf974f8f6d)

Just click on the **Delete** button.

----

### Check if Someone Opened the Malicious File/URL?
The next step of the playbook is to check if someone opened the malicious file/URL.

![image](https://github.com/user-attachments/assets/f1a848b9-fbc7-47ae-becb-d22fcf0ea26d)

To do this, I need to go to the "Log Management" page and check if the C2 (command-and-control) address was accessed. When I filter for the given Felix’s client IP address we can see the traffic

![image](https://github.com/user-attachments/assets/8252e082-81b1-4f3e-acdb-69d9b9d87cdc)

On the raw log of Proxy traffic. We can see the malicious URL: `https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip`

![image](https://github.com/user-attachments/assets/94db3e9e-f0a1-4d70-81c6-2f51f096dedf)

![image](https://github.com/user-attachments/assets/576c7aea-86df-4608-b59f-7b9918603320)

Additionally, I could also see that the coffee.exe has run on the Felix’s host.

![image](https://github.com/user-attachments/assets/813475ab-64c8-4848-89f5-bd8f37b64c62)

In short, it can be concluded that Coffee.exe connects to the C2 address `37.120.233.226`. A malicious address was accessed by the host machine. And the answer is **Opened**.

----

## Containment
Based on the information gathered during the investigation, it is highly likely that the user credentials have been compromised and sensitive information may have been exfiltrated. To prevent further data loss or unauthorized access, it is recommended to isolate the system from the network immediately.

![image](https://github.com/user-attachments/assets/04ab71b4-8e75-4578-bd67-f62aa2fa142a)

Isolation of the host can be made from the endpoint security tab.

> Hostname: Felix
>
> IP Address: 172.16.20.151

----

## Remediation actions
- Educate employees about how to identify and report suspicious emails, and provide training on how to avoid falling for phishing scams.
- Reset any compromised user credentials and implement a strong password policy and strong MFA.
- Implement email filtering and security measures, such as DKIM and SPF, to help detect and block spoofed emails.

----

## MITRE ATT&CK
| MITRE Tactics   | MITRE Techniques |
| ------------- | ------------- |
| Initial Access  | Spearphishing Attachment (T1598.002), Spearphishing Link (T1598.003) |
| Execution | User Execution: T1204, T1204.002, T1204.001 |
| Execution  | Command and Scripting Interpreter: T1059, T1059.003  |
| Execution  | Native API: T1106  |
| Execution  | Windows Management Instrumentation: T1047 |
| Discovery  | Account Discovery: T1087 |
| Discovery  | System Service Discovery: T1007 |
| Command and Control | Application Layer Protocol: T1071 |
| Command and Control  | Non-Standard Port: T1571 |

----

## Artifacts
| IOC Type   | Comment | Value |
| ------------- | ------------- | ------------- |
| URL  | Malicious | `https://files-ld.s3.us-east-2.amazonaws[.]com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip`|
| SMTP Address | Malicious | 103.80.134.63 |
| IPv4 -C2  | Malicious  | 37.120.233.226 |
| Coffee.exe  | Malicious  | cd903ad2211cf7d166646d75e57fb866000f4a3b870b5ec759929be2fd81d334 |
| Email Sent  | Malicious  | `free@coffeeshooop.com` |
| URL  | Malicious  | `coffeeshooop.com` |

----

## Analysis Note
> - Found a string that may be used as part of an injection method Hooks API calls
> - Queries kernel debugger information
> - Contains ability to terminate a process
> - Found a reference to a WMI query string known to be used for VM detection
> - Input file contains API references not part of its Import Address Table (IAT)
> - Possibly checks for the presence of a forensics/monitoring tool
> - Contacts 1 host (`IP: 37.120.233.226`, `Port/Protocol: 3451/TCP`, `Associated Process: PID 4640`, `Details: Romania`)
> - YARA signature match - AsyncRAT
> - Creates a mutant that is known to appear in malware
> - Sample detected by CrowdStrike Static Analysis and ML with relatively high confidence





