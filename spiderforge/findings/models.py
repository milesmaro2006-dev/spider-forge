from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from spiderforge.utils.timestamps import utcnow


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    DISCOVERED = "discovered"
    UNCONFIRMED = "unconfirmed"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    FIXED = "fixed"
    RETEST_PENDING = "retest_pending"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"


class Evidence(BaseModel):
    request: str | None = None
    response: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str | None = None
    payload: str | None = None
    screenshot: str | None = None
    notes: str | None = None


class Finding(BaseModel):
    id: str
    fingerprint: str
    title: str
    category: str
    severity: Severity
    confidence: float = 0.0
    cvss_score: float | None = None
    cvss_vector: str | None = None
    url: str
    method: str = "GET"
    parameter: str | None = None
    description: str = ""
    impact: str = ""
    evidence: Evidence = Field(default_factory=Evidence)
    remediation: str = ""
    status: FindingStatus = FindingStatus.UNCONFIRMED
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)