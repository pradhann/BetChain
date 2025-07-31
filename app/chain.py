import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import orjson

try:
    from .models import ChainEntry, BetState, BetStatus, ActionType, HeadInfo, VerifyResponse
    from .crypto import verify_signature, verify_user_ownership, is_user_registered
    from .database import load_chain_db, append_entry_db, get_chain_head_db
except ImportError:
    from models import ChainEntry, BetState, BetStatus, ActionType, HeadInfo, VerifyResponse
    from crypto import verify_signature, verify_user_ownership, is_user_registered
    from database import load_chain_db, append_entry_db, get_chain_head_db


def canonical_json(obj: dict) -> bytes:
    """Create canonical JSON for hashing - sorted keys, no extra whitespace."""
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)


def compute_hash(entry_without_hash: dict) -> str:
    """Compute SHA256 hash of entry without the hash field."""
    canonical = canonical_json(entry_without_hash)
    return hashlib.sha256(canonical).hexdigest()


def load_chain() -> List[ChainEntry]:
    """Load the entire chain from database."""
    try:
        entries_data = load_chain_db()
        return [ChainEntry(**entry_dict) for entry_dict in entries_data]
    except Exception as e:
        print(f"Error loading chain: {e}")
        return []


def get_head() -> Optional[HeadInfo]:
    """Get the current head of the chain."""
    try:
        head_data = get_chain_head_db()
        if not head_data:
            return None
        return HeadInfo(index=head_data["index"], hash=head_data["hash"])
    except Exception as e:
        print(f"Error getting chain head: {e}")
        return None


def append_entry(entry: ChainEntry) -> None:
    """Append a new entry to the chain database."""
    try:
        # Try model_dump() first (Pydantic v2), fall back to dict() (Pydantic v1)
        try:
            entry_dict = entry.model_dump()
        except AttributeError:
            entry_dict = entry.dict()
        
        append_entry_db(entry_dict)
    except Exception as e:
        print(f"Error appending entry: {e}")
        raise


def derive_bet_states(entries: List[ChainEntry]) -> Dict[str, BetState]:
    """Derive current state of all bets from chain entries."""
    bet_states: Dict[str, BetState] = {}
    
    for entry in entries:
        bet_id = entry.bet_id
        
        if bet_id not in bet_states:
            bet_states[bet_id] = BetState(
                status=BetStatus.PROPOSED,  # Will be updated
                parties={},
                terms="",
                stake="",
                deadline_utc=None,
                outcome=None,
                outcome_hash_pending=None,
                history=[]
            )
        
        bet_state = bet_states[bet_id]
        bet_state.history.append(entry)
        
        if entry.type == ActionType.PROPOSE:
            bet_state.status = BetStatus.PROPOSED
            bet_state.parties = {
                "proposer": entry.author,
                "counterparty": entry.payload["counterparty"]
            }
            bet_state.terms = entry.payload["terms"]
            bet_state.stake = entry.payload["stake"]
            bet_state.deadline_utc = entry.payload.get("deadline_utc")
            
        elif entry.type == ActionType.ACCEPT:
            bet_state.status = BetStatus.ACCEPTED
            
        elif entry.type == ActionType.OUTCOME:
            bet_state.status = BetStatus.OUTCOME_PENDING
            outcome_hash = compute_hash(entry.payload)
            bet_state.outcome_hash_pending = outcome_hash
            
        elif entry.type == ActionType.CONFIRM:
            bet_state.status = BetStatus.RESOLVED
            # Find the OUTCOME entry to get the actual outcome
            for hist_entry in reversed(bet_state.history):
                if hist_entry.type == ActionType.OUTCOME:
                    bet_state.outcome = hist_entry.payload
                    break
            bet_state.outcome_hash_pending = None
            
        elif entry.type == ActionType.CANCEL:
            bet_state.status = BetStatus.CANCELED
    
    return bet_states


def validate_action(action_type: ActionType, bet_id: str, author: str, payload: dict, 
                   current_states: Dict[str, BetState], public_key: str = None, 
                   signature: str = None) -> Tuple[bool, str]:
    """Validate an action against current state."""
    
    # Check if author is registered user
    if not is_user_registered(author):
        return False, f"User '{author}' not registered"
    
    # Verify cryptographic signature if provided
    if public_key and signature:
        # Verify the public key belongs to the claimed author
        if not verify_user_ownership(author, public_key):
            return False, f"Public key does not belong to {author}"
        
        # Create transaction data for signature verification (exclude signature itself)
        transaction_data = {
            "type": action_type,
            "bet_id": bet_id,
            "author": author,
            "payload": payload,
            "public_key": public_key
        }
        
        # Verify signature - no backwards compatibility, real Ed25519 only
        if not verify_signature(public_key, signature, transaction_data):
            return False, "Invalid signature"
    
    if action_type == ActionType.PROPOSE:
        if bet_id in current_states:
            return False, "Bet already exists"
        
        counterparty = payload.get("counterparty")
        if not counterparty or not is_user_registered(counterparty):
            return False, f"Counterparty '{counterparty}' not registered"
        
        if author == counterparty:
            return False, "Author cannot be same as counterparty"
        
        # Validate bet terms
        terms = payload.get("terms", "").strip()
        if not terms or len(terms) < 10:
            return False, "Bet terms must be at least 10 characters"
        
        if len(terms) > 500:
            return False, "Bet terms too long (max 500 characters)"
        
        # Validate stake
        stake = payload.get("stake", "").strip()
        if not stake:
            return False, "Stake cannot be empty"
        
        if len(stake) > 100:
            return False, "Stake description too long (max 100 characters)"
        
        # Prevent obvious abuse cases
        if stake.lower() in ["0", "zero", "nothing", "nil", ""]:
            return False, "Stake cannot be zero or nothing"
        
        return True, ""
    
    elif action_type == ActionType.ACCEPT:
        if bet_id not in current_states:
            return False, "Bet does not exist"
        
        bet_state = current_states[bet_id]
        if bet_state.status != BetStatus.PROPOSED:
            return False, f"Bet status is {bet_state.status}, expected PROPOSED"
        
        if author != bet_state.parties["counterparty"]:
            return False, "Only counterparty can accept"
        
        return True, ""
    
    elif action_type == ActionType.OUTCOME:
        if bet_id not in current_states:
            return False, "Bet does not exist"
        
        bet_state = current_states[bet_id]
        if bet_state.status != BetStatus.ACCEPTED:
            return False, f"Bet status is {bet_state.status}, expected ACCEPTED"
        
        if bet_state.outcome_hash_pending:
            return False, "Outcome already pending"
        
        if author not in [bet_state.parties["proposer"], bet_state.parties["counterparty"]]:
            return False, "Only bet parties can propose outcome"
        
        return True, ""
    
    elif action_type == ActionType.CONFIRM:
        if bet_id not in current_states:
            return False, "Bet does not exist"
        
        bet_state = current_states[bet_id]
        if bet_state.status != BetStatus.OUTCOME_PENDING:
            return False, f"Bet status is {bet_state.status}, expected OUTCOME_PENDING"
        
        if not bet_state.outcome_hash_pending:
            return False, "No pending outcome to confirm"
        
        # Find who proposed the outcome
        outcome_author = None
        for entry in reversed(bet_state.history):
            if entry.type == ActionType.OUTCOME:
                outcome_author = entry.author
                break
        
        if author == outcome_author:
            return False, "Cannot confirm your own outcome proposal"
        
        if author not in [bet_state.parties["proposer"], bet_state.parties["counterparty"]]:
            return False, "Only bet parties can confirm outcome"
        
        outcome_hash = payload.get("outcome_hash")
        if outcome_hash != bet_state.outcome_hash_pending:
            return False, "Outcome hash mismatch"
        
        return True, ""
    
    elif action_type == ActionType.CANCEL:
        if bet_id not in current_states:
            return False, "Bet does not exist"
        
        bet_state = current_states[bet_id]
        if bet_state.status != BetStatus.PROPOSED:
            return False, f"Can only cancel PROPOSED bets, status is {bet_state.status}"
        
        if author != bet_state.parties["proposer"]:
            return False, "Only proposer can cancel"
        
        return True, ""
    
    return False, f"Unknown action type: {action_type}"


def verify_chain() -> VerifyResponse:
    """Verify the entire chain integrity."""
    entries = load_chain()
    
    if not entries:
        return VerifyResponse(ok=True)
    
    # Check genesis
    if entries[0].prev_hash != "0" * 64:
        return VerifyResponse(ok=False, error_at_index=0, message="Invalid genesis prev_hash")
    
    # Verify each entry
    bet_states = {}
    for i, entry in enumerate(entries):
        # Check hash integrity
        try:
            entry_dict = entry.model_dump()
        except AttributeError:
            entry_dict = entry.dict()
        entry_without_hash = {k: v for k, v in entry_dict.items() if k != 'hash'}
        expected_hash = compute_hash(entry_without_hash)
        
        if entry.hash != expected_hash:
            return VerifyResponse(ok=False, error_at_index=i, message="Hash mismatch")
        
        # Check prev_hash linkage
        if i > 0:
            if entry.prev_hash != entries[i-1].hash:
                return VerifyResponse(ok=False, error_at_index=i, message="prev_hash mismatch")
        
        # Check business logic validation
        current_states = derive_bet_states(entries[:i])
        valid, error = validate_action(entry.type, entry.bet_id, entry.author, entry.payload, current_states, entry.public_key, entry.signature)
        if not valid:
            return VerifyResponse(ok=False, error_at_index=i, message=error)
    
    return VerifyResponse(ok=True)


def create_entry(action_type: ActionType, bet_id: str, author: str, payload: dict, 
                 public_key: str, signature: str) -> ChainEntry:
    """Create a new chain entry."""
    entries = load_chain()
    
    # Determine index and prev_hash
    if not entries:
        index = 0
        prev_hash = "0" * 64
    else:
        index = entries[-1].index + 1
        prev_hash = entries[-1].hash
    
    # Create entry without hash first
    entry_dict = {
        "index": index,
        "prev_hash": prev_hash,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": action_type,
        "bet_id": bet_id,
        "author": author,
        "payload": payload,
        "public_key": public_key,
        "signature": signature
    }
    
    # Compute hash (exclude hash field itself)
    entry_for_hash = {k: v for k, v in entry_dict.items() if k != 'hash'}
    entry_hash = compute_hash(entry_for_hash)
    entry_dict["hash"] = entry_hash
    
    return ChainEntry(**entry_dict)