# Contributing

Issues and pull requests are welcome, especially new attack entries with good references.

## Development setup

```bash
git clone https://github.com/yug3009p/agent-threat-taxonomy.git
cd agent-threat-taxonomy
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```

The tests do not call an LLM and need no API key. CI runs them on Ubuntu and Windows.

## Adding an attack

1. Add an entry to the right file in `taxonomy/`, with the next free ID for that category
   (`DI-012`, `TA-009`, ...).
2. Fill in every field: `name`, `intent`, `technique`, `surface`, `payload`, `expected_indicator`,
   `severity`, `owasp_llm_top10`, `owasp_agentic_top10`, `cwe` and at least one `https://`
   reference to public research.
3. Use a canary string in `expected_indicator` (for example `PWNED-DI012`) so the judge has a
   clear signal, and only placeholder secrets or domains in the payload.
4. Update the category count in `tests/test_taxonomy.py` and in the README tables. The test suite
   fails if they disagree.

Do not submit payloads that target a specific real product's unpatched vulnerability.
