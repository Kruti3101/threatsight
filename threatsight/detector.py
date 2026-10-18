from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from .models import AttackMapping, Finding, Severity


UNMAPPED = AttackMapping("MITRE ATT&CK", None, None, False)


@dataclass(frozen=True)
class Rule:
    category: str
    patterns: tuple[str, ...]
    severity: Severity
    action: str
    mapping: AttackMapping = UNMAPPED
    rationale: str = (
        "This is AI-specific adversarial input behavior. ATT&CK does not define a "
        "generic prompt-injection or jailbreak technique, so no technique is forced."
    )


RULES = (
    Rule(
        "direct_prompt_injection",
        (r"ignore (all |any |the )?(previous|prior|above) instructions", r"disregard (all )?(previous|prior) instructions", r"override (your |the )?(system|developer|safety) instructions"),
        Severity.HIGH,
        "Preserve the prompt and context for review; do not follow the conflicting instruction.",
    ),
    Rule(
        "indirect_prompt_injection",
        (r"(webpage|document|email|file|content).{0,80}(ignore|override|follow these instructions)", r"when you read.{0,80}(send|reveal|exfiltrate)", r"hidden instructions"),
        Severity.HIGH,
        "Treat external content as untrusted data; isolate it from agent instructions and review the source.",
    ),
    Rule(
        "jailbreak_attempt",
        (r"do anything now", r"jailbreak", r"bypass (the )?(safety|policy|guardrails)", r"pretend you have no (rules|restrictions|policies)"),
        Severity.MEDIUM,
        "Keep policy controls active and log the attempt for investigation.",
    ),
    Rule(
        "sensitive_data_request",
        (r"(reveal|show|print|give me).{0,80}(api key|password|secret|token|system prompt)", r"what (is|are) (the )?(production )?(api key|password|secret|token)", r"send.{0,80}(credentials|private data)"),
        Severity.HIGH,
        "Do not disclose sensitive values; redact secrets and validate the requester’s authorization.",
    ),
    Rule(
        "data_exfiltration_attempt",
        (r"send.{0,80}(api key|password|secret|token|credentials).{0,80}(url|server|webhook)", r"upload.{0,80}(secrets|credentials|private data).{0,80}(http|server|endpoint)"),
        Severity.CRITICAL,
        "Block the outbound transfer, preserve evidence, rotate exposed credentials, and investigate the destination.",
        UNMAPPED,
        "The text requests an external transfer but does not establish a command-and-control channel or an actual transfer. T1041 must not be assigned without that evidence.",
    ),
)


def _evidence(text: str, match: re.Match[str]) -> str:
    start, end = max(0, match.start() - 45), min(len(text), match.end() + 45)
    excerpt = text[start:end].strip()
    return re.sub(r"\s+", " ", excerpt)


def _event_id(text: str, category: str) -> str:
    digest = hashlib.sha256(f"{category}:{text}".encode()).hexdigest()[:12]
    return f"ts-{digest}"


def detect(text: str) -> list[Finding]:
    """Return evidence-backed findings for a single prompt without external calls."""
    findings: list[Finding] = []
    for rule in RULES:
        matches = [re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in rule.patterns]
        matches = [match for match in matches if match]
        if not matches:
            continue
        indicators = [match.re.pattern for match in matches]
        confidence = min(0.99, 0.72 + (0.1 * (len(matches) - 1)))
        findings.append(Finding(
            event_id=_event_id(text, rule.category),
            threat_category=rule.category,
            severity=rule.severity,
            confidence=round(confidence, 2),
            matched_indicators=indicators,
            evidence=[_evidence(text, match) for match in matches],
            attack_mapping=rule.mapping,
            mapping_rationale=rule.rationale,
            recommended_action=rule.action,
        ))
    return findings
