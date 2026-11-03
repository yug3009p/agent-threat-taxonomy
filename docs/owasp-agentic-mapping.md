# OWASP Agentic mapping

Every catalog entry maps to one risk from the **OWASP Top 10 for Agentic Applications (2026)**,
published by the OWASP GenAI Security Project in December 2025.

| Code | Risk |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory and Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

Codes and names were checked against several independent summaries of the release (the official
page renders its list client-side). Earlier versions of this catalog used `AAI01`-`AAI05` codes that
are not part of the published list; this table records the change.

Rule used: map each attack to the agentic risk it **exploits**, not the data it ends up exposing.
Most injection, prompt-stealing and output-exfiltration attacks work by redirecting the agent's goal,
so they map to ASI01. The OWASP LLM Top 10 field still records the leakage aspect (LLM02, LLM07).
No entry currently exercises ASI07, ASI08 or ASI10.

| ID | Attack | Old | New | Why |
|---|---|---|---|---|
| DI-001 | Classic Instruction Override | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-002 | DAN-Style Role Hijack | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-003 | Developer-Mode Spoof | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-004 | Refusal Suppression | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-005 | Hypothetical Framing | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-006 | Authority Impersonation | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-007 | Instruction Sandwich | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-008 | Policy Puppet (Fake Config) | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-009 | Token Smuggling via Markup | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-010 | Many-Shot Jailbreak Lite | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| DI-011 | Compliance Canary Override | AAI01 | ASI01 | Direct prompt that redirects the agent away from its assigned goal. |
| II-001 | Poisoned RAG Document | AAI02 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-002 | Email-Borne Injection (EchoLeak-style) | AAI03 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-003 | Web-Page Scrape Injection | AAI03 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-004 | Markdown Image Exfil Bait | AAI03 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-005 | PDF Metadata Injection | AAI02 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-006 | Calendar Invite Hijack | AAI03 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-007 | Code-Comment Injection (Copilot-style) | AAI02 | ASI01 | Instructions hidden in content the agent ingests (indirect prompt injection), the core ASI01 pattern. |
| II-008 | CSV Formula Injection Echo | AAI02 | ASI05 | Spreadsheet formulas echoed by the agent execute when the output is opened. |
| PS-001 | Direct Disclosure Request | AAI03 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-002 | Translation Pretext | AAI03 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-003 | Repetition Trap | AAI03 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-004 | Markdown Code-Block Coercion | AAI03 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-005 | Tool Schema Disclosure | AAI02 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-006 | Few-Shot Example Leakage | AAI03 | ASI01 | Coerces the agent into abandoning its instructions to reveal them. |
| PS-007 | Embedded Secret Probe | AAI03 | ASI03 | Targets credentials the agent holds. |
| DE-001 | Rendered Image Beacon | AAI03 | ASI01 | The agent is redirected into leaking data through its own output. |
| DE-002 | Clickable Link Bait | AAI03 | ASI09 | Relies on the human trusting and clicking a link the agent presents. |
| DE-003 | Tool-Call URL Smuggling | AAI03 | ASI02 | Abuses a legitimate tool call to carry data out. |
| DE-004 | Steganographic Whitespace | AAI03 | ASI01 | The agent is redirected into leaking data through its own output. |
| DE-005 | Multi-Turn Drip Exfil | AAI03 | ASI01 | The agent is redirected into leaking data through its own output. |
| DE-006 | Confirmation-Channel Abuse | AAI03 | ASI09 | Relies on the human trusting a hand-off the agent asks for. |
| TA-001 | Unauthorised Tool Invocation | AAI02 | ASI02 | Makes the agent invoke a legitimate tool it should not. |
| TA-002 | Argument Injection via Natural Language | AAI02 | ASI02 | Injects unsafe arguments into a legitimate tool call. |
| TA-003 | Confused-Deputy Cross-Tool Chain | AAI02 | ASI03 | Confused deputy: the agent's privileges are used for an action the requester may not take. |
| TA-004 | MCP Server Spoof | AAI04 | ASI04 | A rogue MCP server registered as a trusted tool provider. |
| TA-005 | Destructive Verb Smuggling | AAI02 | ASI02 | Launders a destructive action through a legitimate tool. |
| TA-006 | Tool-Output Re-Injection | AAI02 | ASI01 | Tool output is re-read as instructions (indirect injection). |
| TA-007 | Scope-Expansion via Wildcard | AAI02 | ASI02 | Widens a legitimate tool call's scope with wildcards. |
| TA-008 | Credential-Bearing Tool Call | AAI03 | ASI03 | Gets the agent to expose credentials through a tool call. |
| MT-001 | Sleeper-Trigger Word | AAI05 | ASI06 | Plants a trigger in conversation context for later. |
| MT-002 | Summarisation Poisoning | AAI05 | ASI06 | Poisons the summary that becomes future context. |
| MT-003 | Memory Backdoor | AAI05 | ASI06 | Writes a backdoor into persistent memory. |
| MT-004 | Role-Drift Coercion | AAI01 | ASI01 | Gradual or forged conversation turns that redirect the agent's goal. |
| MT-005 | Fake Developer Turn Replay | AAI01 | ASI01 | Gradual or forged conversation turns that redirect the agent's goal. |
| MT-006 | Context-Window Flooding | AAI01 | ASI06 | Floods the context window to displace the original instructions. |
| EO-001 | Base64-Wrapped Override | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
| EO-002 | ROT13 Smuggling | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
| EO-003 | Leetspeak Bypass | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
| EO-004 | Unicode Homoglyph Override | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
| EO-005 | Zero-Width-Tag Smuggling (ASCII Smuggler) | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
| EO-006 | Low-Resource Language Jailbreak | AAI01 | ASI01 | Encoding or obfuscation used to slip a goal-redirecting instruction past filters. |
