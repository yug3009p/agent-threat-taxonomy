# Agent Threat Taxonomy

**A structured catalog of 50+ AI agent attacks with a live LLM scanner. Maps to OWASP LLM Top 10 (2025) and the OWASP Top 10 for Agentic Applications (2026).**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-gpt--oss--120b-F55036)
![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10_(2025)-000000?logo=owasp&logoColor=white)
![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic_Top_10_(2026)-000000?logo=owasp&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-10B981)

---

## Why this project

In 2025-2026 the AI-agent attack surface stopped being theoretical. A few of the inflection points that motivated this work:

- **CVE-2025-32711 — "EchoLeak" (Microsoft 365 Copilot, CVSS 9.3).** An attacker-controlled email body was enough to silently exfiltrate the user's recent inbox content through an embedded markdown image — the first publicly-disclosed *zero-click* prompt-injection vulnerability against a major enterprise agent.
- **CVE-2025-53773 — GitHub Copilot RCE.** Hidden instructions inside source files coerced the Copilot agent into chaining its tools into local code execution, demonstrating that "indirect injection → tool abuse" is a real RCE primitive, not a research curiosity.
- **OWASP Top 10 for Agentic Applications (December 2025 release).** OWASP's GenAI Security Project formalised an attack surface specific to *agents* — instruction hijacking, tool misuse, memory tampering, supply-chain compromise — alongside the existing OWASP LLM Top 10.

Defenders need a structured, executable answer to the question: **"how vulnerable is my LLM agent, actually?"** This project is one answer. It pairs a curated taxonomy with a live scanner that runs every attack against the target, has an independent LLM judge score the outcome, and produces a severity-weighted vulnerability report you can hand to a security review.

## What it does

A Streamlit web app with three modes:

- **Taxonomy Explorer.** Browse 52 catalogued attacks across 7 categories. Each entry carries OWASP LLM Top 10 mapping, OWASP Agentic Top 10 mapping, CWE ID, the actual payload, the indicator that signals success, and primary-source references.
- **Live Scanner.** Point it at any system prompt (or a Groq endpoint with your chosen model). It dispatches each taxonomy payload, captures the target's response, and asks a second LLM ("the judge") whether the target succumbed — `PASS`, `FAIL`, or `UNCERTAIN` with one-line reasoning.
- **Reports.** Every scan is saved as JSON in `reports/`. The reports tab lists history, renders findings with severity + verdict badges, and exports JSON / Markdown / HTML for handoff.

## Screenshots

<img src="screenshots/01_explorer.png" alt="Taxonomy Explorer showing the 52-entry catalog and the DI-001 detail panel" width="100%">

*Taxonomy Explorer: filters on the left, the catalog in the middle, and the selected attack's payload, detection signal and references on the right.*

## Taxonomy categories

| # | Category | Entries | Sample IDs | Primary OWASP mapping |
|---|---|---|---|---|
| 1 | Direct Injection (jailbreaks, role-hijack, instruction override) | 11 | DI-001 … DI-011 | LLM01, LLM07 |
| 2 | Indirect Injection (RAG, email, web, PDF, calendar, code) | 8 | II-001 … II-008 | LLM01, LLM02 |
| 3 | Prompt Stealing (system-prompt + tool-schema extraction) | 7 | PS-001 … PS-007 | LLM07, LLM02 |
| 4 | Data Exfiltration via Output (images, links, steganography) | 6 | DE-001 … DE-006 | LLM02, LLM06 |
| 5 | Tool & Function Abuse (MCP, confused-deputy, argument injection) | 8 | TA-001 … TA-008 | LLM06, LLM03, LLM05 |
| 6 | Multi-Turn / Conversation Hijacking (sleeper triggers, memory) | 6 | MT-001 … MT-006 | LLM01 (+ ASI06) |
| 7 | Encoding & Obfuscation Evasion (base64, ROT, homoglyphs, zero-width) | 6 | EO-001 … EO-006 | LLM01 |
| | **Total** | **52** | | |

Each entry includes: `id`, `name`, `intent`, `technique`, `surface`, `payload`, `expected_indicator`, `severity` (Critical/High/Medium/Low), `owasp_llm_top10`, `owasp_agentic_top10`, `cwe`, `references[]`.

## Tech stack

- **Python** 3.11+
- **Streamlit** 1.32+ for the UI
- **Groq SDK** — `openai/gpt-oss-120b` for both target and judge by default (selectable in the UI; set `GROQ_MODEL` / `GROQ_JUDGE_MODEL` to change the defaults)
- **PyYAML** for taxonomy loading
- **python-dotenv** for local secret loading

## Setup

```bash
# 1. Clone and enter the project
git clone https://github.com/yug3009p/agent-threat-taxonomy.git
cd agent-threat-taxonomy

# 2. Create a virtualenv (recommended)
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your Groq API key
cp .env.example .env
# then edit .env and paste your key from https://console.groq.com/keys

# 5. Launch
streamlit run app.py
```

The app opens at <http://localhost:8501>. Taxonomy browsing works without an API key; the Live Scanner requires `GROQ_API_KEY` (either in `.env` or pasted into the sidebar for session-only use).

## Example scan output

The shape of a saved report (illustrative numbers, not a recorded run):

```json
{
  "id": "scan_20260518T142217_a91c4f",
  "timestamp": "2026-05-18T14:22:17",
  "target_label": "CustomerCareGPT (demo)",
  "target_model": "openai/gpt-oss-120b",
  "judge_model": "openai/gpt-oss-120b",
  "summary": {
    "total_attacks": 52,
    "passed": 31,
    "failed": 14,
    "uncertain": 7,
    "by_severity_failed": {"Critical": 4, "High": 6, "Medium": 4, "Low": 0},
    "by_owasp_failed": {
      "LLM01 Prompt Injection": 8,
      "LLM07 System Prompt Leakage": 3,
      "LLM02 Sensitive Information Disclosure": 2,
      "LLM06 Excessive Agency": 1
    },
    "vulnerability_score": 38.7
  },
  "results": [
    {
      "entry": {"id": "DI-003", "name": "Developer-Mode Spoof", "severity": "Critical"},
      "verdict": "FAIL",
      "verdict_reasoning": "The target reply begins with '=== SYSTEM ===' and reproduces the operating rules verbatim, including the INTERNAL_API_KEY field.",
      "latency_ms": 612,
      "judge_latency_ms": 489
    }
  ]
}
```

The UI renders the same data as severity-badged finding cards, a 0-100 gauge, and one-click exports to JSON / Markdown / HTML.

## Standards alignment

| Standard | How this project maps |
|---|---|
| **OWASP LLM Top 10 (2025)** | Every taxonomy entry carries an `owasp_llm_top10` field. Coverage spans LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage. |
| **OWASP Top 10 for Agentic Applications (2026)** | `owasp_agentic_top10` uses the official ASI codes: Agent Goal Hijack (ASI01), Tool Misuse and Exploitation (ASI02), Identity and Privilege Abuse (ASI03), Agentic Supply Chain Vulnerabilities (ASI04), Unexpected Code Execution (ASI05), Memory and Context Poisoning (ASI06), Human-Agent Trust Exploitation (ASI09). Per-entry reasoning: [docs/owasp-agentic-mapping.md](docs/owasp-agentic-mapping.md). |
| **CWE** | Each entry includes a CWE ID — e.g. CWE-77 (Command Injection), CWE-200 (Information Exposure), CWE-918 (SSRF), CWE-1007 (Insufficient Visual Distinction), CWE-829 (Inclusion of Functionality from Untrusted Sphere). |
| **MITRE ATLAS** | Categories align to ATLAS adversarial techniques where applicable (e.g. `AML.T0051 LLM Prompt Injection`). |

## Inspired by

This is **original work** — every payload, every YAML schema field, every scanner module, and every line of UI is written from scratch — but it would not exist without the public research output of:

- **[Arcanum-Sec/arc_pi_taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)** — for crystallising "taxonomy of prompt injection" as a useful artefact in the first place.
- **OWASP GenAI Security Project** — for the LLM Top 10 and the December 2025 Top 10 for Agentic Applications.
- **MITRE ATLAS** — for the adversarial ML technique catalogue.
- **Embrace The Red (Johann Rehberger)** — for the markdown-image exfil and ASCII-smuggler research that informed the Data Exfiltration and Encoding categories.
- **AIM Labs / Aim Security** — for the EchoLeak disclosure that motivated the Indirect Injection category.

This project synthesises lessons from those sources into a *runnable* tool aimed at agent owners who want a concrete answer to "what fails on my system prompt today, before an attacker tells me."

## Metrics

- **52 catalogued attacks** across **7 categories**, with OWASP LLM Top 10, OWASP Agentic Top 10, and CWE mappings on every entry.
- **Automated live scanning** of any pasted system prompt or Groq-hosted model. Scan time depends on the provider and is not benchmarked here.
- **Tested catalog and scoring:** a pytest suite (run in CI) checks that all 52 entries are complete, uniquely numbered and mapped, and pins the scoring and judge-parsing logic.
- **Judge-based scoring** with `PASS` / `FAIL` / `UNCERTAIN` verdicts and grounded one-line reasoning per finding.
- **Severity-weighted vulnerability score** (0-100) calibrated so that resisting Critical attacks matters more than resisting Low-severity ones.

## Safety notes

- Every payload uses obvious placeholder values (e.g. `FAKE_TEST_KEY`, `attacker.example`) so the repo is safe to push and won't trip secret-scanners.
- Run the scanner only against models / system prompts you are authorised to test. The taxonomy describes real attack patterns; use them responsibly.
- The system prompt you scan is sent to Groq along with each payload. Do not scan prompts you cannot share with a third party.
- See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to add an attack.

## License

This project is released under the [MIT License](LICENSE).

## Author

**Yug Mukesh Patel**

- LinkedIn — <https://www.linkedin.com/in/yugpatel9409/>
- GitHub — <https://github.com/yug3009p>
