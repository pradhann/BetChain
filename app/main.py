from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from typing import List, Dict
import uuid
from .models import (
    ActionRequest, ApiResponse, BetState, HeadInfo, VerifyResponse,
    ActionType, ProposePayload, AcceptPayload, OutcomePayload, 
    ConfirmPayload, CancelPayload, LoginRequest, AuthResponse
)
from .chain import (
    load_chain, derive_bet_states, validate_action, create_entry, 
    append_entry, get_head, verify_chain
)
from .crypto import get_user_public_key, register_user, is_user_registered

app = FastAPI(title="BetChain", description="Hash-chained betting between friends")

# Mount static files
import os
static_dir = "static" if os.path.exists("static") else "app/static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.post("/tx", response_model=ApiResponse)
async def submit_transaction(request: ActionRequest):
    """Submit a new transaction (betting action)."""
    try:
        # Use the bet_id from the request (required for signature verification)
        bet_id = request.bet_id
        
        if not bet_id:
            raise HTTPException(status_code=400, detail="bet_id is required")
        
        # Load current chain and derive states
        entries = load_chain()
        current_states = derive_bet_states(entries)
        
        # Validate the action (including signature verification)
        valid, error = validate_action(
            request.type, bet_id, request.author, request.payload, current_states,
            request.public_key, request.signature
        )
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        
        # Create and append new entry
        entry = create_entry(request.type, bet_id, request.author, request.payload,
                           request.public_key, request.signature)
        append_entry(entry)
        
        # Get updated state
        updated_entries = load_chain()
        updated_states = derive_bet_states(updated_entries)
        bet_state = updated_states.get(bet_id)
        
        head = get_head()
        
        return ApiResponse(
            ok=True,
            head=head,
            bet_state=bet_state
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bets", response_model=List[Dict])
async def get_bets():
    """Get list of all bets with minimal state."""
    try:
        entries = load_chain()
        bet_states = derive_bet_states(entries)
        
        result = []
        for bet_id, state in bet_states.items():
            last_updated = state.history[-1].timestamp if state.history else None
            result.append({
                "bet_id": bet_id,
                "parties": state.parties,
                "status": state.status,
                "stake": state.stake,
                "terms": state.terms,
                "deadline": state.deadline_utc,
                "last_updated": last_updated
            })
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bet/{bet_id}", response_model=BetState)
async def get_bet(bet_id: str):
    """Get full state and history for a specific bet."""
    try:
        entries = load_chain()
        bet_states = derive_bet_states(entries)
        
        if bet_id not in bet_states:
            raise HTTPException(status_code=404, detail="Bet not found")
        
        return bet_states[bet_id]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/head", response_model=HeadInfo)
async def get_chain_head():
    """Get current chain head info."""
    try:
        head = get_head()
        if not head:
            # Return genesis state
            return HeadInfo(index=-1, hash="0" * 64)
        return head
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/verify", response_model=VerifyResponse)
async def verify_chain_integrity():
    """Verify the entire chain integrity."""
    try:
        return verify_chain()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/", response_class=HTMLResponse)
async def get_ui():
    """Serve the main UI."""
    try:
        index_path = "static/index.html" if os.path.exists("static/index.html") else "app/static/index.html"
        with open(index_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html>
        <head><title>BetChain</title></head>
        <body>
            <h1>BetChain API</h1>
            <p>API is running. UI not yet available.</p>
            <ul>
                <li><a href="/docs">API Documentation</a></li>
                <li><a href="/bets">Get Bets (JSON)</a></li>
                <li><a href="/head">Get Head (JSON)</a></li>
                <li><a href="/verify">Verify Chain (JSON)</a></li>
                <li><a href="/keys/Aayush">Get Aayush's keys</a></li>
            </ul>
        </body>
        </html>
        """)


@app.post("/register")
async def register_user_endpoint(request: dict):
    """Register a new user with their public key."""
    try:
        username = request.get("username")
        public_key = request.get("public_key")
        
        print(f"DEBUG: Registration request - username: {username}, public_key: {public_key[:50]}...")
        
        if not username or not public_key:
            raise HTTPException(status_code=400, detail="Missing username or public_key")
        
        if register_user(username, public_key):
            return {"ok": True, "message": f"User '{username}' registered successfully"}
        else:
            raise HTTPException(status_code=400, detail="User already exists or invalid public key")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users")
async def get_registered_users():
    """Get list of all registered users."""
    from .crypto import USER_REGISTRY
    return {"users": list(USER_REGISTRY.keys())}


@app.get("/keys/{username}")
async def get_user_key(username: str):
    """Get the public key for a registered user."""
    try:
        public_key = get_user_public_key(username)
        print(f"DEBUG: Retrieved key for {username}: {public_key[:20]}...")
        return {"username": username, "public_key": public_key}
    except ValueError as e:
        print(f"DEBUG: User {username} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)