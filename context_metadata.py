"""Parse contest case metadata without treating customer text as authority.

Only use metadata when the caller has identified a trusted case-start event.
Whether a Kakao payload represents such an event must be established from the
actual platform contract; the syntax alone cannot prove authenticity.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_FIELDS = {"id", "상담 인입 일시", "인입창구", "인입 계정"}


@dataclass(frozen=True)
class CaseMetadata:
    case_id: str
    intake_time: str | None
    channel: str | None
    account: str | None


def parse_case_start(text: str, *, trusted_start: bool) -> tuple[CaseMetadata | None, str]:
    """Return (metadata, remaining message); never parse untrusted input.

    A trusted caller must check event provenance and decide that this starts a
    new evaluation case. Duplicate/unknown fields and partial metadata are
    rejected without dropping any user text. An account label is not evidence
    that the sender has rights to a requested order.
    """
    if not trusted_start or not isinstance(text, str):
        return None, text
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip().lower() != "case metadata":
        return None, text
    parsed: dict[str, str] = {}
    end = 1
    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            end = i + 1
            break
        match = re.fullmatch(r"\s*-\s*([^:]+):\s*(.*?)\s*", line.rstrip("\r\n"))
        if not match:
            return None, text
        name, value = match.group(1).strip(), match.group(2).strip()
        if name not in _FIELDS or name in parsed or not value:
            return None, text
        parsed[name] = value
    else:
        return None, text
    case_id = parsed.get("id", "")
    if not _CASE_ID.fullmatch(case_id):
        return None, text
    return CaseMetadata(case_id, parsed.get("상담 인입 일시"), parsed.get("인입창구"), parsed.get("인입 계정")), "".join(lines[end:])
