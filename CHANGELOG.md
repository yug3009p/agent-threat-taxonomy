# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- `owasp_agentic_top10` now uses the official OWASP Top 10 for Agentic Applications (2026) codes
  (ASI01-ASI10). The previous `AAI01`-`AAI05` codes were not part of the published list. Every
  entry's old and new code, with the reason, is in `docs/owasp-agentic-mapping.md`, and a test
  rejects any code outside the official list.

### Fixed
- The judge-reply parser crashed with `AttributeError` when the judge model returned a JSON list
  instead of an object; such replies now count as `UNCERTAIN`.
- README: the example report contained a Low-severity failure although the catalog has no Low
  entries; it is now labelled as illustrative and internally consistent. Removed unmeasured scan
  timings.
- Removed unused imports and f-strings without placeholders.

### Added
- pytest suite: catalog completeness (52 entries, unique IDs, category counts and ID prefixes,
  OWASP / CWE / reference format), severity-weighted scoring, risk bands and judge-output parsing.
- CI on Ubuntu and Windows, SECURITY.md, CONTRIBUTING.md, this changelog, a real screenshot.

## [1.0.0] - 2026-05-18

Not tagged; refers to the first version on `main`.

### Added
- 52-entry attack catalog in 7 categories, live scanner with an LLM judge, Streamlit UI and
  JSON / Markdown / HTML report export.
