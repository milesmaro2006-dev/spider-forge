from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


_AV = {AttackVector.NETWORK: 0.85, AttackVector.ADJACENT: 0.62, AttackVector.LOCAL: 0.55, AttackVector.PHYSICAL: 0.2}
_AC = {AttackComplexity.LOW: 0.77, AttackComplexity.HIGH: 0.44}
_PR_U = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.62, PrivilegesRequired.HIGH: 0.27}
_PR_C = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.68, PrivilegesRequired.HIGH: 0.5}
_UI = {UserInteraction.NONE: 0.85, UserInteraction.REQUIRED: 0.62}
_IMP = {Impact.NONE: 0.0, Impact.LOW: 0.22, Impact.HIGH: 0.56}


@dataclass
class CvssV31:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.HIGH
    integrity: Impact = Impact.HIGH
    availability: Impact = Impact.HIGH

    # ------------------------ Calculator ------------------------------ #

    def _iss(self) -> float:
        c = _IMP[self.confidentiality]
        i = _IMP[self.integrity]
        a = _IMP[self.availability]
        return 1 - ((1 - c) * (1 - i) * (1 - a))

    def base_score(self) -> float:
        iss = self._iss()
        if iss <= 0:
            return 0.0

        sc = self.scope == Scope.CHANGED
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if sc else 6.42 * iss

        pr_table = _PR_C if sc else _PR_U
        expl = (
            8.22
            * _AV[self.attack_vector]
            * _AC[self.attack_complexity]
            * pr_table[self.privileges_required]
            * _UI[self.user_interaction]
        )

        if impact <= 0:
            return 0.0

        base = min((1.08 if sc else 1.0) * (impact + expl), 10.0)
        return round(_roundup(base), 1)

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}"
            f"/AC:{self.attack_complexity.value}"
            f"/PR:{self.privileges_required.value}"
            f"/UI:{self.user_interaction.value}"
            f"/S:{self.scope.value}"
            f"/C:{self.confidentiality.value}"
            f"/I:{self.integrity.value}"
            f"/A:{self.availability.value}"
        )

    def severity(self) -> str:
        s = self.base_score()
        if s == 0:
            return "none"
        if s < 4.0:
            return "low"
        if s < 7.0:
            return "medium"
        if s < 9.0:
            return "high"
        return "critical"


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup function."""
    i = int(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


# --------------------------- Presets ---------------------------------- #

PRESETS: dict[str, CvssV31] = {
    "reflected_xss": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "stored_xss": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "sqli": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "ssti": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "cmdi": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "path_traversal": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "cors_reflection_creds": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "open_redirect": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "missing_header": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "cookie_flag": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "info_leak": CvssV31(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
}


def score_for(category: str) -> tuple[float, str] | None:
    """Return ``(score, vector)`` for a known category prefix, else ``None``."""
    key = category.split(".")[0]
    preset = PRESETS.get(key)
    if preset is None:
        # try full category
        preset = PRESETS.get(category)
    if preset is None:
        return None
    return preset.base_score(), preset.vector()