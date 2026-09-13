from __future__ import annotations

from typing import Sequence
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select

from spiderforge.database.engine import session_scope
from spiderforge.database.models import FindingRow, Project, Scan


class ProjectRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def create(self, name: str) -> Project:
        if self._session:
            project = Project(name=name)
            self._session.add(project)
            self._session.flush()
            return project
        with session_scope() as session:
            project = Project(name=name)
            session.add(project)
            return project

    def get_by_name(self, name: str) -> Project | None:
        if self._session:
            stmt = select(Project).where(Project.name == name)
            return self._session.scalars(stmt).first()
        with session_scope() as session:
            stmt = select(Project).where(Project.name == name)
            return self._session.scalars(stmt).first()

    def get_or_create(self, name: str) -> Project:
        project = self.get_by_name(name)
        if not project:
            project = self.create(name)
        return project

    def get_all(self) -> Sequence[Project]:
        if self._session:
            stmt = select(Project)
            return self._session.scalars(stmt).all()
        with session_scope() as session:
            stmt = select(Project)
            return session.scalars(stmt).all()

    def delete(self, project_id: int) -> bool:
        if self._session:
            project = self._session.get(Project, project_id)
            if project:
                self._session.delete(project)
                return True
            return False
        with session_scope() as session:
            project = session.get(Project, project_id)
            if project:
                session.delete(project)
                return True
            return False


class ScanRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def create(self, project_id: int, scan_uid: str, target: str, profile: str = "balanced", workspace_path: str = "") -> Scan:
        if self._session:
            scan = Scan(
                project_id=project_id,
                scan_uid=scan_uid,
                target=target,
                profile=profile,
                status="running",
                workspace_path=workspace_path
            )
            self._session.add(scan)
            self._session.flush()
            return scan
        with session_scope() as session:
            scan = Scan(
                project_id=project_id,
                scan_uid=scan_uid,
                target=target,
                profile=profile,
                status="running",
                workspace_path=workspace_path
            )
            session.add(scan)
            return scan

    def get_by_uid(self, scan_uid: str) -> Scan | None:
        if self._session:
            stmt = select(Scan).where(Scan.scan_uid == scan_uid)
            return self._session.scalars(stmt).first()
        with session_scope() as session:
            stmt = select(Scan).where(Scan.scan_uid == scan_uid)
            return session.scalars(stmt).first()

    def update_status(self, scan_uid: str, status: str, finished_at=None) -> bool:
        if self._session:
            stmt = select(Scan).where(Scan.scan_uid == scan_uid)
            scan = self._session.scalars(stmt).first()
            if scan:
                scan.status = status
                if finished_at:
                    scan.finished_at = finished_at
                return True
            return False
        with session_scope() as session:
            stmt = select(Scan).where(Scan.scan_uid == scan_uid)
            scan = session.scalars(stmt).first()
            if scan:
                scan.status = status
                if finished_at:
                    scan.finished_at = finished_at
                return True
            return False

    def finish(self, scan_id: int, status: str = "completed") -> bool:
        if self._session:
            scan = self._session.get(Scan, scan_id)
            if scan:
                scan.status = status
                scan.finished_at = datetime.utcnow()
                return True
            return False
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = status
                scan.finished_at = datetime.utcnow()
                return True
            return False


class FindingRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def create(self, scan_id: int, finding_uid: str, fingerprint: str, title: str, category: str, severity: str, url: str, **kwargs) -> FindingRow:
        if self._session:
            finding = FindingRow(
                scan_id=scan_id,
                finding_uid=finding_uid,
                fingerprint=fingerprint,
                title=title,
                category=category,
                severity=severity,
                url=url,
                **kwargs
            )
            self._session.add(finding)
            self._session.flush()
            return finding
        with session_scope() as session:
            finding = FindingRow(
                scan_id=scan_id,
                finding_uid=finding_uid,
                fingerprint=fingerprint,
                title=title,
                category=category,
                severity=severity,
                url=url,
                **kwargs
            )
            session.add(finding)
            return finding

    def get_by_scan(self, scan_id: int) -> Sequence[FindingRow]:
        if self._session:
            stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
            return self._session.scalars(stmt).all()
        with session_scope() as session:
            stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
            return session.scalars(stmt).all()
