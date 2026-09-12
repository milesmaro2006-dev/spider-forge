from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from spiderforge.evidence.hashes import hash_file, sha256_bytes
from spiderforge.evidence.http import HttpCapture, capture
from spiderforge.evidence.models import EvidenceArtifact, EvidenceBundle
from spiderforge.findings.models import Finding


class EvidenceCollector:
    """Persist evidence artifacts for findings under a scan workspace."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.evidence_dir = self.workspace / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------- HTTP capture --------------------------- #

    def capture_http(
        self,
        finding: Finding,
        *,
        method: str,
        url: str,
        request_headers: dict[str, str] | None = None,
        request_body: str | None = None,
        response=None,
    ) -> EvidenceBundle:
        cap = capture(
            method=method,
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            response=response,
        )
        bundle = self._bundle_for(finding.id)

        req_path = bundle_dir = Path(bundle.dir) / "request.txt"
        req_path.write_text(cap.request, encoding="utf-8")
        bundle.add(self._artifact(req_path, "request"))

        if cap.response:
            resp_path = Path(bundle.dir) / "response.txt"
            resp_path.write_text(cap.response, encoding="utf-8")
            bundle.add(self._artifact(resp_path, "response"))

        meta_path = Path(bundle.dir) / "meta.json"
        meta_path.write_text(
            json.dumps(
                {
                    "url": cap.url,
                    "method": cap.method,
                    "status_code": cap.status_code,
                    "request_headers": cap.request_headers,
                    "response_headers": cap.response_headers,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        bundle.add(self._artifact(meta_path, "note"))

        self._write_index(bundle)
        return bundle

    # --------------------------- Raw text ------------------------------ #

    def capture_text(
        self, finding: Finding, *, name: str, content: str, kind: str = "note"
    ) -> EvidenceArtifact:
        bundle = self._bundle_for(finding.id)
        path = Path(bundle.dir) / name
        path.write_text(content, encoding="utf-8")
        art = self._artifact(path, kind)
        bundle.add(art)
        self._write_index(bundle)
        return art

    def capture_bytes(
        self,
        finding: Finding,
        *,
        name: str,
        content: bytes,
        kind: str = "raw",
        content_type: str | None = None,
    ) -> EvidenceArtifact:
        bundle = self._bundle_for(finding.id)
        path = Path(bundle.dir) / name
        path.write_bytes(content)
        art = self._artifact(path, kind)
        art.content_type = content_type
        bundle.add(art)
        self._write_index(bundle)
        return art

    def attach_screenshot(self, finding: Finding, src: Path) -> EvidenceArtifact | None:
        if not src.exists():
            return None
        bundle = self._bundle_for(finding.id)
        dst = Path(bundle.dir) / "screenshot.png"
        dst.write_bytes(src.read_bytes())
        art = self._artifact(dst, "screenshot")
        art.content_type = "image/png"
        bundle.add(art)
        self._write_index(bundle)
        return art

    # -------------------------- Bulk export ---------------------------- #

    def export_findings(self, findings: Iterable[Finding]) -> Path:
        out = self.workspace / "findings.json"
        payload = [f.model_dump(mode="json") for f in findings]
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return out

    # --------------------------- Internals ----------------------------- #

    def _bundle_for(self, finding_id: str) -> EvidenceBundle:
        d = self.evidence_dir / finding_id
        d.mkdir(parents=True, exist_ok=True)
        bundle_path = d / "bundle.json"
        if bundle_path.exists():
            data = json.loads(bundle_path.read_text(encoding="utf-8"))
            b = EvidenceBundle(finding_id=finding_id, dir=str(d))
            for a in data.get("artifacts", []):
                b.artifacts.append(
                    EvidenceArtifact(
                        kind=a["kind"],
                        path=a["path"],
                        sha256=a.get("sha256", ""),
                        size=a.get("size", 0),
                        content_type=a.get("content_type"),
                        meta=a.get("meta") or {},
                    )
                )
            return b
        return EvidenceBundle(finding_id=finding_id, dir=str(d))

    def _artifact(self, path: Path, kind: str) -> EvidenceArtifact:
        info = hash_file(path)
        return EvidenceArtifact(
            kind=kind,
            path=str(path.relative_to(self.workspace)),
            sha256=info["sha256"],
            size=info["size"],
        )

    def _write_index(self, bundle: EvidenceBundle) -> None:
        idx = Path(bundle.dir) / "bundle.json"
        idx.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")