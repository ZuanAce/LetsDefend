# Incident Report
> Event ID: 257
> 
> Rule Name: SOC282 - Phishing Alert - Deceptive Mail Detected
## Alert
Based on the information that the alert provided, it seems that a suspicious link has
been detected in an email sent to `Felix` from the email address
`free@coffeeshoop.com` with the SMTP IP address `103.80.134.63`. The Alert is
triggered by the SOC282 rule **Phishing Alert - Deceptive Mail Detected**. The device action is marked as "allowed", indicating that no action was taken by the Email security product to prevent or block the related mail. The email was sent to `Felix` on `May, 13, 2024, 09:22 AM`. The subject line of the email is `Free Coffee Voucher`.

![image](https://github.com/user-attachments/assets/a96724bf-c6ac-4460-815c-baf9ea926553)

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
As the playbook suggests, I started investigating the alert by parsing email information.

![image](https://github.com/user-attachments/assets/bcad23b9-28aa-4735-a785-89b3b9de107e)

The first step in the playbook is to gather information about the email. This includes:
- When was the email sent?
- What is the SMTP address of the email?
- What is the sender's email address?
- What is the recipient's email address?
- Is the content of the email suspicious?
- Are there any attachments in the email?

By answering these questions, I could gather more information about the email and
determine whether it is a legitimate message or a phishing attempt. On the email
security tab, I could simply search for Felix.

![image](https://github.com/user-attachments/assets/3d00cd62-cb69-4271-b410-cd36e660a549)

![image](https://github.com/user-attachments/assets/e3c695c6-380b-4ca0-b503-d954b6d88b0d)

![image](https://github.com/user-attachments/assets/4a1d2190-1fa8-45e1-81b4-31d360f1d910)

> [!IMPORTANT]
> There were several red flags indicating that this is a phishing email
> - [X] Suspicious email: free@coffeeshooop.com
> - [X] Contains phrases like **Hurry** and **This offer expires soon**, which are
meant to pressure the user, a common tactic in phishing attempts.

From the email analysis, I had the information that the playbook requires
| Questions | Answers |
| ------------- | ------------- |
| When was it sent?  | May, 13, 2024, 09:22 AM  |
| What is the SMTP address of the email?  |103.80.134.63  |
| What is the sender's email address?  | free@coffeeshooop.com  |
| What is the recipient's email address?  | Felix@letsdefend.io  |
| Is the content of the email suspicious?  | Yes  |
| Are there any attachments in the email?  | `https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip`  |

---- 

## Analysis
### Are there attachments or URLs in the email?
As part of the investigation process, the first step of the playbook requires me to
check if the email contains any attachments or URLs.

![image](https://github.com/user-attachments/assets/d11d5a52-d053-41b9-9e74-044527e8a30c)

From the email analysis, the playbook’s answer is **YES**, the mail contains URL and attachment.

----

### Analyze URL/Attachment?

The next step is to further analyze the suspicious URL or attachment using third-party sandboxing tools to obtain additional insights and help determine if it is malicious or not.

![image](https://github.com/user-attachments/assets/ae17b2f0-c8e6-48c9-91e7-a3da2a1c15c9)

I analyzed the URL using [VirusTotal](https://www.virustotal.com/gui/url/bb6460ae86e964854fcb2c379bb937f63611e6be3a25ded254e5ad4e9498b278). Virus Total is an online service that analyzes suspicious files and URLs to detect types of malware and malicious content using antivirus engines and website scanners. 

![image](https://github.com/user-attachments/assets/2e3438e5-f205-4d91-90cd-0b80696d7d76)

The results showed that 8 antivirus engines flagged the URL as malicious including Fortinet, BitDefender, and MalwareURL. In the crowdsourced context tab, it is categorized as silent builder. This indicates a high probability that the URL is malicious and poses a significant threat to the recipient's system and personal information.

As part of the analysis in the second step, I used Hybrid Analysis to simulate the malware and gather more information about the threat.

![image](https://github.com/user-attachments/assets/ef280341-277a-41d2-a064-d3c82f973cbd)

The [report](https://www.hybrid-analysis.com/sample/6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389) indicates that the URL has a threat score of 100/100, signifying a high level of maliciousness if exploited. Upon examining the SHA256 hash `6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389`, it was linked to a file named `Coffee.exe`.

![image](https://github.com/user-attachments/assets/d52e98c1-8269-4e50-a8f0-96a26d695955)

Further [finding](https://www.hybrid-analysis.com/sample/6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389) revealed that the URL provided in the email imitates the Adobe login
page, making it difficult for the user to differentiate between the real and fake login
page.

> [!NOTE]
> Additional Findings
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

From the analysis, the playbook’s answer is **Malicious**, the URL contained in the email is malicious. 

----

### Check If Mail Delivered to User?
In the 3rd step of the playbook, I was required to check if the mail was delivered to the user.

![image](https://github.com/user-attachments/assets/36e9636a-9226-4845-b84e-b88da6471d63)

I could determine this by looking at the "device action" part of the alert details, which
will tell us if the email was delivered to the user's inbox, marked as spam, or blocked by
the email security system.

![image](https://github.com/user-attachments/assets/902453f4-741d-4ef2-8bf5-44985407f59d)

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




