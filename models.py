# models.py
from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime

class EvidenceItem(BaseModel):
    id: str                           # e.g., "evtx:4625:2025-10-20T14:05:13Z:line123"
    type: Literal["winlog","sshlog","policy_extract","metric"]
    source: str                       # path/host/file
    event_id: Optional[str] = None    # e.g., "4625", "4740"
    timestamp: Optional[datetime] = None
    attributes: dict                  # arbitrary parsed fields (ip, user, count, etc.)
    hash: str                         # hash of the raw line / record for provenance

class ThreatSignal(BaseModel):
    name: str                         # "BruteForce-SSH-on-Windows"
    score: float                      # 0..1
    features: dict                    # derived metrics: failures_per_min, unique_ips, etc.
    supporting_evidence_ids: List[str]

class PolicyClause(BaseModel):
    policy_id: str                    # "CIS v8 6.3" or your doc anchor
    title: str
    requirement: str
    priority: Literal["P0","P1","P2"]

class PolicyGap(BaseModel):
    clause: PolicyClause
    status: Literal["met","gap","unknown"]
    justification: str
    linked_evidence_ids: List[str]    # empty → treated as "no evidence"
    confidence: float

class Recommendation(BaseModel):
    gap_policy_id: str
    action: str
    rationale: str
    linked_evidence_ids: List[str]
    effort: Literal["Quick Win","Longer-term"]
    owner: str
    metric_of_success: str

class State(BaseModel):
    evidence: List[EvidenceItem] = []
    signals: List[ThreatSignal] = []
    candidate_clauses: List[PolicyClause] = []
    gaps: List[PolicyGap] = []
    recommendations: List[Recommendation] = []
