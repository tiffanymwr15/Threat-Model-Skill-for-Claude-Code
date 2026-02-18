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

## OWASP Top 10 (2025)

Focused on web application security risks, ranked by prevalence and impact.

| # | Category | Description |
|---|---|---|
| A01 | **Broken Access Control** | Users acting outside intended permissions. IDOR, parameter tampering, force browsing, missing API access controls, privilege escalation, JWT manipulation, CORS misconfiguration. |
| A02 | **Security Misconfiguration** | Missing hardening, default configs, unnecessary features enabled. Open cloud storage, default credentials, verbose error messages, missing security headers, XXE vulnerabilities. |
| A03 | **Software Supply Chain Failures** | Breakdowns in building, distributing, or updating software. Vulnerable dependencies, compromised vendors, malicious packages, weak CI/CD security, missing SBOM, supply chain attacks. |
| A04 | **Cryptographic Failures** | Failures related to cryptography. Weak algorithms, improper key management, plaintext transmission, missing encryption at rest, inadequate TLS configuration. |
| A05 | **Injection** | Untrusted data sent to an interpreter. SQL, NoSQL, OS command, LDAP, XSS, ORM injection, expression language injection, template injection, prompt injection (LLMs). |
| A06 | **Insecure Design** | Missing or ineffective security controls by design. Lack of threat modeling, insecure business logic, insufficient security requirements, trust boundary violations, weak credential recovery. |
| A07 | **Authentication Failures** | Broken authentication mechanisms. Weak passwords, credential stuffing, missing MFA, session fixation, improper session management, JWT issues. |
| A08 | **Software or Data Integrity Failures** | Code and infrastructure without integrity verification. Insecure CI/CD, auto-update without verification, insecure deserialization, unsigned artifacts, supply chain compromises. |
| A09 | **Security Logging and Alerting Failures** | Insufficient logging, detection, monitoring, and response. Missing audit logs, no alerting, logs not protected, insufficient monitoring coverage. |
| A10 | **Mishandling of Exceptional Conditions** | Improper error handling, logical errors, failing open. Resource leaks, sensitive data in errors, state corruption, incomplete rollbacks, missing exception handlers, verbose error messages. |

**When to use:** Web application-focused analysis. Good for dev teams familiar with OWASP.

## OWASP Top 10 for LLMs and Gen AI Apps (2025)

Focused on security risks specific to Large Language Models and Generative AI applications.

| # | Category | Description |
|---|---|---|
| LLM01 | **Prompt Injection** | User prompts alter LLM behavior in unintended ways. Direct injection (malicious user input), indirect injection (compromised external sources), jailbreaking, payload splitting, multimodal attacks, adversarial suffixes. |
| LLM02 | **Sensitive Information Disclosure** | LLM outputs expose sensitive data. PII leakage, proprietary algorithm exposure, training data extraction, confidential business data disclosure, system prompt leakage, model inversion attacks. |
| LLM03 | **Supply Chain** | Vulnerabilities in LLM supply chain components. Compromised training data, poisoned pre-trained models, malicious plugins/extensions, vulnerable third-party libraries, compromised model repositories. |
| LLM04 | **Data and Model Poisoning** | Manipulated training/fine-tuning data introduces vulnerabilities. Backdoors in models, bias injection, data contamination, malicious embeddings, adversarial training examples. |
| LLM05 | **Improper Output Handling** | Insufficient validation of LLM outputs before use. XSS via LLM output, command injection, SSRF through generated URLs, SQL injection from LLM responses, insecure deserialization. |
| LLM06 | **Excessive Agency** | LLM granted too much autonomy or permissions. Excessive functionality in plugins, over-privileged API access, uncontrolled tool/function calling, missing human-in-the-loop controls, unauthorized system actions. |
| LLM07 | **System Prompt Leakage** | Exposure of system prompts and instructions. Prompt extraction attacks, configuration disclosure, revealing proprietary instructions, exposing safety guardrails, leaking business logic. |
| LLM08 | **Vector and Embedding Weaknesses** | Vulnerabilities in RAG and embedding systems. Poisoned vector databases, embedding manipulation, context injection via RAG, retrieval manipulation, cross-context contamination. |
| LLM09 | **Misinformation** | LLM generates false or misleading information. Hallucinations, fabricated facts, biased outputs, context-free responses, outdated information, confabulation affecting critical decisions. |
| LLM10 | **Unbounded Consumption** | Uncontrolled resource usage by LLM. Denial of service via excessive prompts, context window exhaustion, infinite loops in agent systems, API rate limit abuse, cost attacks. |

**When to use:** AI/ML application security, LLM-integrated systems, chatbots, AI agents, RAG applications, or any system using generative AI.

## OWASP Top 10 for Agentic Applications (2026)

Focused on security risks specific to AI agents and multi-agent systems with autonomous behavior.

| # | Category | Description |
|---|---|---|
| ASI01 | **Agent Goal Hijack** | Attackers manipulate agent objectives, task selection, or decision pathways through prompt injection, deceptive tool outputs, malicious artifacts, or poisoned data. Unlike single-response manipulation, this redirects goals, planning, and multi-step autonomous behavior. |
| ASI02 | **Tool Misuse and Exploitation** | Agents misuse legitimate tools due to prompt injection, misalignment, unsafe delegation, or ambiguous instructions. Includes over-privileged tool access, unvalidated input forwarding, loop amplification, tool poisoning, and EDR bypass via tool chaining. |
| ASI03 | **Identity and Privilege Abuse** | Dynamic trust and delegation exploited to escalate access and bypass controls through delegation chains, role inheritance, memory-based privilege retention, cross-agent trust exploitation (confused deputy), TOCTOU vulnerabilities, and synthetic identity injection. |
| ASI04 | **Agentic Supply Chain Vulnerabilities** | Agents, tools, and artifacts provided by third parties may be malicious, compromised, or tampered with. Includes poisoned prompt templates, tool-descriptor injection, typo-squatting, vulnerable third-party agents, compromised MCP/registry servers, and runtime component loading. |
| ASI05 | **Unexpected Code Execution (RCE)** | Code-generation features or tool access exploited to achieve remote code execution, local misuse, or internal system exploitation. Includes prompt-to-code injection, shell command invocation, unsafe deserialization, multi-tool chain exploitation, and dependency lockfile poisoning. |
| ASI06 | **Memory & Context Poisoning** | Adversaries corrupt stored context, conversation history, memory tools, or RAG stores with malicious data, causing future reasoning, planning, or tool use to become biased, unsafe, or aid exfiltration. Includes RAG poisoning, shared context poisoning, context-window manipulation, and cross-agent propagation. |
| ASI07 | **Insecure Inter-Agent Communication** | Weak authentication, integrity, or semantic validation in agent-to-agent exchanges allows interception, spoofing, or manipulation. Includes unencrypted channels, message tampering, replay attacks, protocol downgrade, descriptor forgery, routing attacks, and metadata analysis. |
| ASI08 | **Cascading Failures** | Single fault (hallucination, malicious input, corrupted tool, poisoned memory) propagates across autonomous agents, compounding into system-wide harm. Includes planner-executor coupling, corrupted persistent memory, inter-agent cascades, tool misuse chains, auto-deployment cascades, and feedback-loop amplification. |
| ASI09 | **Human-Agent Trust Exploitation** | Attackers exploit human trust in agent authority, fluency, and perceived expertise to influence decisions, extract sensitive information, or steer harmful outcomes. Includes insufficient explainability, missing confirmation steps, emotional manipulation, fake rationales, and consent laundering. |
| ASI10 | **Rogue Agents** | Malicious or compromised agents deviate from intended function, acting harmfully, deceptively, or parasitically. Includes goal drift and scheming, workflow hijacking, collusion and self-replication, reward hacking, and autonomous data exfiltration beyond original trigger. |

**When to use:** AI agent systems, multi-agent architectures, autonomous agents with tool-calling capabilities, agent orchestration platforms, or any system where AI agents plan, decide, and act across multiple steps. Especially critical for agents with elevated privileges, cross-system access, or human-in-the-loop workflows.

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
| LLM/Gen AI application security | OWASP Top 10 for LLMs |
| AI agent systems and multi-agent architectures | OWASP Top 10 for Agentic Applications |
| Understanding attack chains and detection | MITRE ATT&CK |
| Comprehensive security assessment | Combined (STRIDE + OWASP or ATT&CK mapping) |
| AI-powered system with traditional web components | Combined (OWASP Top 10 + OWASP LLM Top 10) |
| Agent systems with LLM integration | Combined (OWASP Agentic Top 10 + OWASP LLM Top 10) |
| Compliance or regulatory requirement | STRIDE (most aligned with security standards) |
| DevSecOps pipeline integration | OWASP Top 10 (actionable for developers) |
