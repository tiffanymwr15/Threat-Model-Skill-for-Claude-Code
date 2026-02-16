# Threat Model Generator

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skill that analyzes systems and applications to produce structured threat model reports.

Point it at a system description, URL, or codebase and it walks you through a full threat modeling workflow. It identifies assets, entry points, and threats, then recommends prioritized mitigations. The output is a ready-to-share markdown report.

I plan to iterate and improve over time with more functionality.

## Supported Frameworks

- **STRIDE** (default) - General-purpose threat categorization. Best for most applications.
- **OWASP Top 10** - Web application-focused. Maps directly to common web vulnerabilities.
- **MITRE ATT&CK** - Adversary-focused. Good for understanding attack chains and building detection.
- **Combined** - Use multiple frameworks for comprehensive coverage.

## What You Can Feed It

The skill accepts any combination of:

- A system description (architecture, components, data flows)
- A URL (documentation, design docs, architecture diagrams)
- Local files or a codebase to review
- A specific framework preference
- A scope to narrow the analysis

It figures out the system from whatever you provide.

## How It Works

1. **Gathers context** - Asks clarifying questions or reads your provided inputs to understand the system
2. **Selects framework** - Recommends a framework based on your system, or uses your preference
3. **Identifies assets and entry points** - Enumerates what needs protection and where attackers interact
4. **Enumerates threats** - Applies the framework systematically to each component and data flow
5. **Recommends mitigations** - Proposes specific, prioritized countermeasures
6. **Reviews with you** - Presents a summary for your approval before writing the full report
7. **Writes the report** - Saves a structured markdown report to your project

## Report Output

The generated report includes:

- Executive summary
- System overview with architecture, data flows, trust boundaries, and user roles
- Asset and entry point inventory
- Detailed threat analysis with risk ratings (likelihood x impact)
- Risk matrix visualization
- Prioritized mitigation roadmap (P1/P2/P3)
- Documented assumptions and limitations

## Installation

1. Copy the `threat-model` folder into your project's `.claude/skills/` directory:

```
your-project/
  .claude/
    skills/
      threat-model/
        SKILL.md
        frameworks.md
```

2. The skill will be available as `/threat-model` in Claude Code.

## Usage

Run the skill from Claude Code:

```
/threat-model
```

Then describe your system, paste a URL, or point it at files in your project. A few examples:

```
/threat-model Analyze the authentication flow in our Express API.
              Users log in with email/password, we issue JWTs,
              and store refresh tokens in Redis.
```

```
/threat-model Review the system described at https://docs.example.com/architecture
```

```
/threat-model Look at the code in src/ and threat model this application using OWASP Top 10
```

## Contributing

This skill is open for improvements. Some ideas:

- Additional framework support (PASTA, LINDDUN for privacy, etc.)
- Diagram generation (Mermaid data flow diagrams, attack trees)
- Integration with issue trackers to create tickets from findings
- Templates for specific system types (microservices, serverless, mobile apps)
- Severity scoring refinements (CVSS mapping, DREAD)
- Export formats beyond markdown (PDF, HTML, JSON)

If you have ideas or want to contribute, open an issue or submit a pull request.

## License

MIT
