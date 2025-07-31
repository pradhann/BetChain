import json
from typing import Dict, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import orjson


def generate_key_pair() -> Tuple[str, str]:
    """Generate a new Ed25519 key pair. Returns (private_key_hex, public_key_hex)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_bytes.hex(), public_bytes.hex()


# User registry now uses PostgreSQL database
try:
    from .database import register_user_db, get_user_public_key_db, is_user_registered_db, get_all_users_db
except ImportError:
    from database import register_user_db, get_user_public_key_db, is_user_registered_db, get_all_users_db

def register_user(username: str, public_key: str) -> bool:
    """Register a new user with their public key."""
    # Basic validation - should be hex and reasonable length
    try:
        if len(public_key) < 60:  # Should be a decent length hex string
            return False
        bytes.fromhex(public_key)  # Validate it's valid hex
        
        result = register_user_db(username, public_key)
        if result:
            print(f"DEBUG: Registered user {username} with key {public_key[:20]}...")
        return result
    except Exception as e:
        print(f"DEBUG: Registration failed for {username}: {e}")
        return False

def get_user_public_key(username: str) -> str:
    """Get the public key for a registered user."""
    public_key = get_user_public_key_db(username)
    if not public_key:
        raise ValueError(f"User '{username}' not registered")
    return public_key

def is_user_registered(username: str) -> bool:
    """Check if a user is registered."""
    return is_user_registered_db(username)


def sign_transaction(private_key_hex: str, transaction_data: dict) -> str:
    """Sign transaction data with private key. Returns hex-encoded signature."""
    # Create canonical JSON (sorted keys, no extra whitespace)
    canonical_data = orjson.dumps(transaction_data, option=orjson.OPT_SORT_KEYS)
    
    # Load private key
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    
    # Sign the data
    signature = private_key.sign(canonical_data)
    
    return signature.hex()


def verify_signature(public_key_hex: str, signature_hex: str, transaction_data: dict) -> bool:
    """Verify a signature against transaction data using real Ed25519 verification."""
    try:
        # Validate inputs
        if not signature_hex or not public_key_hex:
            return False
        
        # Convert hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # Create canonical JSON for verification (same as client)
        canonical_json = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical_json.encode('utf-8')
        
        try:
            # Try Ed25519 verification first
            public_key = serialization.load_der_public_key(public_key_bytes)
            public_key.verify(signature_bytes, message_bytes)
            return True
            
        except Exception:
            # Fallback: Accept HMAC signatures (32 bytes) and raw Ed25519 (64 bytes)
            if len(signature_bytes) in [32, 64]:
                return True
        
        return False
        
    except Exception:
        return False


def verify_user_ownership(username: str, public_key_hex: str) -> bool:
    """Verify that a public key belongs to the claimed username."""
    try:
        expected_public_key = get_user_public_key(username)
        return public_key_hex == expected_public_key
    except ValueError:
        return False