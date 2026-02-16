# Threat Modeling Frameworks Reference

## STRIDE

Microsoft's framework for categorizing threats. Apply each category to every component and data flow.

| Category | Question | Example Threats |
|---|---|---|
| **Spoofing** | Can an attacker pretend to be someone/something else? | Credential theft, session hijacking, IP spoofing, forged tokens |
| **Tampering** | Can an attacker modify data they shouldn't? | SQL injection, parameter manipulation, man-in-the-middle, file modification |
| **Repudiation** | Can an attacker deny performing an action? | Missing audit logs, unsigned transactions, no accountability trail |
| **Information Disclosure** | Can an attacker access data they shouldn't? | Data leaks, verbose errors, insecure storage, side-channel attacks |
| **Denial of Service** | Can an attacker prevent legitimate use? | Resource exhaustion, API abuse, algorithmic complexity attacks, lock-out |
| **Elevation of Privilege** | Can an attacker gain higher access than intended? | IDOR, privilege escalation, broken access control, container escape |

**When to use:** General-purpose threat modeling for any system. Good default choice.

## OWASP Top 10 (2021)

Focused on web application security risks, ranked by prevalence and impact.

| # | Category | Description |
|---|---|---|
| A01 | **Broken Access Control** | Users acting outside intended permissions. IDOR, missing function-level access control, CORS misconfiguration. |
| A02 | **Cryptographic Failures** | Failures related to cryptography. Weak algorithms, improper key management, plaintext transmission, missing encryption at rest. |
| A03 | **Injection** | Untrusted data sent to an interpreter. SQL, NoSQL, OS command, LDAP, XSS (reflected/stored/DOM). |
| A04 | **Insecure Design** | Missing or ineffective security controls by design. Missing threat modeling, insecure business logic, insufficient input validation patterns. |
| A05 | **Security Misconfiguration** | Missing hardening, default configs, unnecessary features enabled. Open cloud storage, default credentials, verbose errors, missing security headers. |
| A06 | **Vulnerable and Outdated Components** | Using components with known vulnerabilities. Unpatched libraries, unsupported frameworks, missing SCA scanning. |
| A07 | **Identification and Authentication Failures** | Broken authentication. Weak passwords, credential stuffing, missing MFA, session fixation. |
| A08 | **Software and Data Integrity Failures** | Code and infrastructure without integrity verification. Insecure CI/CD, auto-update without verification, insecure deserialization. |
| A09 | **Security Logging and Monitoring Failures** | Insufficient logging, detection, monitoring, and response. Missing audit logs, no alerting, logs not protected. |
| A10 | **Server-Side Request Forgery (SSRF)** | App fetches remote resources without validating user-supplied URL. Internal service access, cloud metadata exposure, firewall bypass. |

**When to use:** Web application-focused analysis. Good for dev teams familiar with OWASP.

## MITRE ATT&CK (Application-Relevant Tactics)

Adversary-focused framework. These tactics are most relevant for application threat modeling.

| Tactic | Description | Relevant Techniques |
|---|---|---|
| **Initial Access** | How attackers get in | Phishing, exploit public-facing app, supply chain compromise, valid accounts |
| **Execution** | How attackers run code | Command injection, scripting, serverless execution, user execution |
| **Persistence** | How attackers maintain access | Account manipulation, implant code, scheduled tasks, valid accounts |
| **Privilege Escalation** | How attackers gain higher access | Exploitation for privilege escalation, access token manipulation, valid accounts |
| **Defense Evasion** | How attackers avoid detection | Obfuscation, indicator removal, masquerading, modify cloud compute |
| **Credential Access** | How attackers steal credentials | Brute force, credential dumping, input capture, unsecured credentials |
| **Discovery** | How attackers learn about the environment | Account discovery, cloud service enumeration, network scanning |
| **Lateral Movement** | How attackers move through systems | Exploitation of remote services, internal spear phishing, use alternate auth |
| **Collection** | How attackers gather target data | Data from cloud storage, data from information repositories, input capture |
| **Exfiltration** | How attackers steal data | Exfiltration over web service, automated exfiltration, transfer data to cloud |
| **Impact** | How attackers cause damage | Data destruction, data encryption for impact, defacement, resource hijacking |

**When to use:** When focused on understanding adversary behavior and building detection capabilities. Good for security operations teams.

## Choosing a Framework

| Scenario | Recommended Framework |
|---|---|
| General application threat model | STRIDE |
| Web application security review | OWASP Top 10 |
| Understanding attack chains and detection | MITRE ATT&CK |
| Comprehensive security assessment | Combined (STRIDE + OWASP or ATT&CK mapping) |
| Compliance or regulatory requirement | STRIDE (most aligned with security standards) |
| DevSecOps pipeline integration | OWASP Top 10 (actionable for developers) |
