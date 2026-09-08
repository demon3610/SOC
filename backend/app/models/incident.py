from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[int] = None


class IncidentResponse(BaseModel):
    id: int
    project_id: int
    title: str
    description: Optional[str] = None
    mitigation: Optional[list] = None
    severity: str
    status: str
    assigned_to: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    notes: list[dict] = []
    os_types: list[str] = []
    affected_ips: list[str] = []
    risk_score: Optional[float] = None
    risk_average: Optional[float] = None
    mitre_tags: list[dict] = []
    primary_ip: Optional[str] = None
