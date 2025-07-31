from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
import uuid


class ActionType(str, Enum):
    PROPOSE = "PROPOSE"
    ACCEPT = "ACCEPT"
    OUTCOME = "OUTCOME"
    CONFIRM = "CONFIRM"
    CANCEL = "CANCEL"


class BetStatus(str, Enum):
    PROPOSED = "PROPOSED"
    ACCEPTED = "ACCEPTED"
    OUTCOME_PENDING = "OUTCOME_PENDING"
    RESOLVED = "RESOLVED"
    CANCELED = "CANCELED"


class ChainEntry(BaseModel):
    index: int
    prev_hash: str
    timestamp: str
    type: ActionType
    bet_id: str
    author: str
    payload: Dict[str, Any]
    public_key: str  # hex-encoded public key
    signature: str   # hex-encoded signature
    hash: str


class ProposePayload(BaseModel):
    counterparty: str
    terms: str
    stake: str
    deadline_utc: Optional[str] = None


class AcceptPayload(BaseModel):
    pass


class OutcomePayload(BaseModel):
    result: str = Field(..., pattern="^(Aayush_wins|Shitosh_wins|Subhay_wins|Nripesh_wins|void)$")
    evidence_url: Optional[str] = None
    note: Optional[str] = None


class ConfirmPayload(BaseModel):
    outcome_hash: str


class CancelPayload(BaseModel):
    pass


class ActionRequest(BaseModel):
    type: ActionType
    bet_id: Optional[str] = None
    author: str
    payload: Dict[str, Any]
    public_key: str  # hex-encoded public key
    signature: str   # hex-encoded signature


class BetState(BaseModel):
    status: BetStatus
    parties: Dict[str, str]
    terms: str
    stake: str
    deadline_utc: Optional[str]
    outcome: Optional[Dict[str, Any]]
    outcome_hash_pending: Optional[str]
    history: List[ChainEntry]


class HeadInfo(BaseModel):
    index: int
    hash: str


class ApiResponse(BaseModel):
    ok: bool
    head: Optional[HeadInfo] = None
    bet_state: Optional[BetState] = None
    message: Optional[str] = None


class VerifyResponse(BaseModel):
    ok: bool
    error_at_index: Optional[int] = None
    message: Optional[str] = None


class LoginRequest(BaseModel):
    username: str


class AuthResponse(BaseModel):
    ok: bool
    username: Optional[str] = None
    message: Optional[str] = None