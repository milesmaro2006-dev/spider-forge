from __future__ import annotations

from dataclasses import dataclass, field

from spiderforge.findings.models import Finding


@dataclass
class ReportMeta:
    project_name: str
    scan_id: str
    target: str
    started_at: str
    finished_at: str | None = None
    author: str = "SpiderForge"


@dataclass
class ReportContext:
    meta: ReportMeta
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    recon: dict = field(default_factory=dict)
    discovery: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    module_errors: dict[str, str] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in self.findings:
            groups.setdefault(f.severity.value, []).append(f)
        return groups