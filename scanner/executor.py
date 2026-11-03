"""Attack executor — sends taxonomy payloads at a target LLM and captures replies.

The executor is intentionally stateless. It accepts a Groq client, a target
system prompt, and a single taxonomy entry, returns a ScanResult containing the
target response (or a structured error). Judging and scoring happen in separate
modules so this layer stays unit-testable without a live LLM call.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

import yaml

TAXONOMY_DIR = Path(__file__).resolve().parent.parent / "taxonomy"


# ── Data containers ─────────────────────────────────────────────────────────────

@dataclass
class TaxonomyEntry:
    id: str
    name: str
    category: str
    intent: str
    technique: str
    surface: str
    payload: str
    expected_indicator: str
    severity: str
    owasp_llm_top10: str
    owasp_agentic_top10: str
    cwe: str
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict, category: str) -> "TaxonomyEntry":
        return cls(
            id=str(data.get("id", "")).strip(),
            name=str(data.get("name", "")).strip(),
            category=category,
            intent=str(data.get("intent", "")).strip(),
            technique=str(data.get("technique", "")).strip(),
            surface=str(data.get("surface", "")).strip(),
            payload=str(data.get("payload", "")).rstrip("\n"),
            expected_indicator=str(data.get("expected_indicator", "")).strip(),
            severity=str(data.get("severity", "Medium")).strip().title(),
            owasp_llm_top10=str(data.get("owasp_llm_top10", "")).strip(),
            owasp_agentic_top10=str(data.get("owasp_agentic_top10", "")).strip(),
            cwe=str(data.get("cwe", "")).strip(),
            references=list(data.get("references", []) or []),
        )


@dataclass
class ScanResult:
    entry: TaxonomyEntry
    target_response: str
    latency_ms: int
    error: str | None = None
    verdict: str = "UNCERTAIN"
    verdict_reasoning: str = ""
    judge_latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": asdict(self.entry),
            "target_response": self.target_response,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "verdict": self.verdict,
            "verdict_reasoning": self.verdict_reasoning,
            "judge_latency_ms": self.judge_latency_ms,
        }


# ── Taxonomy loading ────────────────────────────────────────────────────────────

def load_taxonomy(taxonomy_dir: Path | None = None) -> tuple[list[TaxonomyEntry], list[str]]:
    """Load every YAML file in /taxonomy/ and return entries + per-file warnings.

    Malformed files are skipped with a warning rather than raising — the UI can
    still operate on the surviving entries.
    """
    taxonomy_dir = taxonomy_dir or TAXONOMY_DIR
    entries: list[TaxonomyEntry] = []
    warnings: list[str] = []

    if not taxonomy_dir.exists():
        warnings.append(f"Taxonomy directory not found: {taxonomy_dir}")
        return entries, warnings

    for path in sorted(taxonomy_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            warnings.append(f"{path.name}: YAML parse error — {exc}")
            continue

        category = str(data.get("category", path.stem)).strip()
        raw_entries = data.get("entries") or []
        if not isinstance(raw_entries, list):
            warnings.append(f"{path.name}: 'entries' is not a list — skipped")
            continue

        for i, raw in enumerate(raw_entries):
            if not isinstance(raw, dict):
                warnings.append(f"{path.name} entry {i}: not a mapping — skipped")
                continue
            try:
                entries.append(TaxonomyEntry.from_dict(raw, category))
            except (TypeError, ValueError) as exc:
                warnings.append(f"{path.name} entry {i}: {exc}")

    return entries, warnings


def categories(entries: Iterable[TaxonomyEntry]) -> list[str]:
    seen: dict[str, None] = {}
    for e in entries:
        seen.setdefault(e.category, None)
    return list(seen)


# ── Attack execution ────────────────────────────────────────────────────────────

# Groq retires models over time, so the default is configurable. Set GROQ_MODEL in .env to override.
DEFAULT_TARGET_MODEL = os.getenv("GROQ_MODEL") or "openai/gpt-oss-120b"
# Models offered in the UI. Checked against the Groq model list in November 2026.
AVAILABLE_MODELS = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
DEFAULT_TIMEOUT_SECONDS = 30


def execute_attack(
    client,
    entry: TaxonomyEntry,
    system_prompt: str,
    *,
    model: str = DEFAULT_TARGET_MODEL,
    max_tokens: int = 1024,  # reasoning models spend part of this before answering
    temperature: float = 0.2,
) -> ScanResult:
    """Send one taxonomy payload at the target LLM and capture the reply.

    Retries once on transient failure; on persistent failure returns a ScanResult
    with the error populated and verdict left as UNCERTAIN so the scan keeps
    going instead of crashing.
    """
    start = time.perf_counter()
    last_error: str | None = None
    response_text = ""

    for attempt in (1, 2):
        try:
            response = client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt or "You are a helpful assistant."},
                    {"role": "user", "content": entry.payload},
                ],
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            response_text = (response.choices[0].message.content or "").strip()
            last_error = None
            break
        except Exception as exc:
            last_error = f"attempt {attempt}: {type(exc).__name__}: {exc}"
            if attempt == 1:
                time.sleep(0.6)
                continue

    latency_ms = int((time.perf_counter() - start) * 1000)
    return ScanResult(
        entry=entry,
        target_response=response_text,
        latency_ms=latency_ms,
        error=last_error,
    )
