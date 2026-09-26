"""
Shared data structures for ClankerShield.

Kept as plain dataclasses (not pydantic) for the internal pipeline so the
scanning/risk/patch code has no framework dependency. FastAPI request bodies
use pydantic models defined in main.py; everything returned to the client is
converted with `to_dict()` / `dataclasses.asdict`.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional
import uuid


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def stable_finding_id(file: str, type_: str, rule_id: str, snippet: str) -> str:
    """
    Deterministic finding identity, independent of line number.

    Line numbers shift whenever an earlier line in the same file is edited
    (e.g. a patch elsewhere in the file), but the same rule catching the same
    code should still "be" the same finding across a rescan - that stability
    is what lets a finding stay resolvable/verifiable across a patch cycle.
    """
    import hashlib
    digest = hashlib.sha1(f"{file}|{type_}|{rule_id}|{snippet}".encode("utf-8")).hexdigest()
    return f"finding_{digest[:12]}"


@dataclass
class RiskBreakdown:
    severity_weight: int = 0
    exploitability: int = 0
    exposure: int = 0
    data_sensitivity: int = 0
    reachability: int = 0
    evidence_strength: int = 0
    scanner_confidence: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    id: str
    type: str
    title: str
    severity: str  # critical | high | medium | low
    cwe: str
    file: str
    line: int
    end_line: int
    snippet: str
    explanation: str
    impact: str
    remediation: str
    sources: list = field(default_factory=list)          # e.g. ["builtin", "secret-scanner"]
    rule_ids: list = field(default_factory=list)
    risk_score: int = 0
    risk_band: str = "low"
    risk_breakdown: dict = field(default_factory=dict)
    confidence: float = 0.7
    evidence_refs: list = field(default_factory=list)
    attack_path: list = field(default_factory=list)
    patch_available: bool = False
    verification_status: str = "DETECTED"  # DETECTED | CONFIRMED | STATICALLY_VERIFIED | FIXED | REOPENED
    lifecycle_status: str = "OPEN"  # OPEN | CONFIRMED | FALSE_POSITIVE | ACCEPTED_RISK | IN_PROGRESS | FIXED | REOPENED
    suppression_reason: str = ""
    suppressed_at: Optional[str] = None
    classification: str = "vulnerability"  # vulnerability | secret | misconfiguration | dependency_risk | hygiene
    advisory_ids: list = field(default_factory=list)
    advisory_urls: list = field(default_factory=list)
    cvss: Optional[float] = None
    resolved: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PipelineStage:
    id: str
    label: str
    status: str = "pending"  # pending | running | completed | failed | skipped
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    result_count: Optional[int] = None
    detail: str = ""
    error: Optional[str] = None
    available: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Patch:
    id: str
    repo_id: str
    finding_id: str
    file: str
    diff: str
    explanation: str
    base_file_hash: str
    changed_files: list
    changed_lines: int
    safety_checks: list
    created_at: str = field(default_factory=now_iso)
    status: str = "draft"  # draft | applied | rejected | stale
    new_content: str = ""  # kept server-side only, never serialized to the client as-is
    new_hash: str = ""
    backup_path: str = ""
    patch_type: str = "deterministic"
    patch_source: str = "builtin-rule"
    model: str = ""
    verification_status: str = "NOT_RUN"

    def public_dict(self) -> dict:
        d = asdict(self)
        d.pop("new_content", None)
        return d


@dataclass
class Repository:
    id: str
    name: str
    source_type: str  # "demo" | "upload"
    workspace_path: str
    owner_id: str = "dev-local"
    created_at: str = field(default_factory=now_iso)
    files_analyzed: int = 0
    frameworks: list = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    findings: dict = field(default_factory=dict)          # finding_id -> Finding
    baseline_findings: dict = field(default_factory=dict)  # snapshot right after first scan
    patches: dict = field(default_factory=dict)            # patch_id -> Patch
    pipeline: list = field(default_factory=list)            # list[PipelineStage.to_dict()]
    scan_count: int = 0
    last_scanned_at: Optional[str] = None
    graph: dict = field(default_factory=dict)
    verification_history: list = field(default_factory=list)
    scan_history: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    audit_events: list = field(default_factory=list)
    ai_configured: bool = False

    def summary_dict(self) -> dict:
        findings = list(self.findings.values())
        return {
            "id": self.id,
            "name": self.name,
            "source_type": self.source_type,
            "owner_id": self.owner_id if self.owner_id != "dev-local" else None,
            "created_at": self.created_at,
            "files_analyzed": self.files_analyzed,
            "frameworks": self.frameworks,
            "scan_count": self.scan_count,
            "last_scanned_at": self.last_scanned_at,
            "ai_configured": self.ai_configured,
            "metrics": compute_metrics(findings),
            "scan_history": self.scan_history,
            "coverage": self.coverage,
            "findings": [f.to_dict() for f in findings],
            "pipeline": self.pipeline,
            "inventory": self.inventory,
        }


def compute_metrics(findings: list) -> dict:
    suppressed = [f for f in findings if f.lifecycle_status in {"FALSE_POSITIVE", "ACCEPTED_RISK"}]
    active = [f for f in findings if not f.resolved and f.lifecycle_status not in {"FALSE_POSITIVE", "ACCEPTED_RISK"}]
    neutralized = [f for f in findings if f.resolved]
    critical = [f for f in active if f.severity == "critical"]
    high = [f for f in active if f.severity == "high"]
    medium = [f for f in active if f.severity == "medium"]
    low = [f for f in active if f.severity == "low"]

    if findings:
        # Contextual security risk score: 100 minus a severity-weighted penalty for every
        # *active* (unresolved) finding, capped so a heavily-flawed repo
        # still reads as clearly distinct from a hypothetical zero score.
        penalty = min(95, (len(critical) * 18) + (len(high) * 9) + (len(medium) * 4) + (len(low) * 1))
        score = max(5, 100 - penalty)
    else:
        score = 100

    return {
        "threats_detected": len(findings),
        "threats_neutralized": len(neutralized),
        "suppressed_count": len(suppressed),
        "active_vulnerabilities": len(active),
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": len(medium),
        "low_count": len(low),
        "security_risk_score": score,
        # Compatibility alias for older clients. New UI and API documentation
        # use security_risk_score because this deterministic metric is not AI.
        "ai_security_score": score,
    }
