# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in this tool. Report it privately through
GitHub's **Report a vulnerability** button on the repository's Security tab, or by email to
yug3009p@gmail.com.

If you find that a payload in this catalog works against a real, deployed product, do not open an
issue or a pull request with details. Report it to that vendor through their disclosure process.

You can expect an acknowledgement within 7 days. This is a personal open-source project, so fixes
are best-effort.

## Intended use

- The catalog describes known attack patterns so defenders can test their own systems. Run the
  scanner only against models and system prompts you are authorised to test.
- Payloads use placeholder values (for example `FAKE_TEST_KEY`, `attacker.example`) and canary
  strings, not working exploits against specific products.
- The scanned system prompt and every payload are sent to Groq. The judge is also an LLM, so its
  verdicts are advisory.

## Scope

In scope: this repository's code and catalog. Out of scope: vulnerabilities in dependencies or in
Groq's service (report those upstream).
