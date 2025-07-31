import os
import json
from typing import List, Dict, Optional
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:biUbUNcQTNAtQUsryHXhGgROJzcOGZfl@nozomi.proxy.rlwy.net:49835/railway")

# Fix for Railway PostgreSQL URL (they use postgres:// but SQLAlchemy needs postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    username = Column(String(50), primary_key=True)
    public_key = Column(Text, nullable=False)

class ChainEntry(Base):
    __tablename__ = "chain_entries"
    
    index = Column(Integer, primary_key=True)
    prev_hash = Column(Text, nullable=False)
    timestamp = Column(String(50), nullable=False)  # ISO format string
    type = Column(String(20), nullable=False)
    bet_id = Column(String(100), nullable=False)
    author = Column(String(50), nullable=False)
    payload = Column(JSONB, nullable=False)
    public_key = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    hash = Column(Text, nullable=False)

# Create tables
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User operations
def register_user_db(username: str, public_key: str) -> bool:
    """Register a new user with their public key."""
    db = SessionLocal()
    try:
        # Check if user already exists
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            return False
        
        # Create new user
        user = User(username=username, public_key=public_key)
        db.add(user)
        db.commit()
        return True
    except Exception as e:
        print(f"Error registering user: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def get_user_public_key_db(username: str) -> Optional[str]:
    """Get the public key for a registered user."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        return user.public_key if user else None
    finally:
        db.close()

def is_user_registered_db(username: str) -> bool:
    """Check if a user is registered."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        return user is not None
    finally:
        db.close()

def get_all_users_db() -> List[str]:
    """Get list of all registered users."""
    db = SessionLocal()
    try:
        users = db.query(User.username).all()
        return [user.username for user in users]
    finally:
        db.close()

# Chain operations
def load_chain_db() -> List[Dict]:
    """Load the entire chain from database."""
    db = SessionLocal()
    try:
        entries = db.query(ChainEntry).order_by(ChainEntry.index).all()
        return [
            {
                "index": entry.index,
                "prev_hash": entry.prev_hash,
                "timestamp": entry.timestamp,
                "type": entry.type,
                "bet_id": entry.bet_id,
                "author": entry.author,
                "payload": entry.payload,
                "public_key": entry.public_key,
                "signature": entry.signature,
                "hash": entry.hash
            }
            for entry in entries
        ]
    finally:
        db.close()

def append_entry_db(entry_dict: Dict) -> None:
    """Append a new entry to the chain."""
    db = SessionLocal()
    try:
        entry = ChainEntry(
            index=entry_dict["index"],
            prev_hash=entry_dict["prev_hash"],
            timestamp=entry_dict["timestamp"],
            type=entry_dict["type"],
            bet_id=entry_dict["bet_id"],
            author=entry_dict["author"],
            payload=entry_dict["payload"],
            public_key=entry_dict["public_key"],
            signature=entry_dict["signature"],
            hash=entry_dict["hash"]
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        print(f"Error appending entry: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_chain_head_db() -> Optional[Dict]:
    """Get the last entry in the chain."""
    db = SessionLocal()
    try:
        entry = db.query(ChainEntry).order_by(ChainEntry.index.desc()).first()
        if not entry:
            return None
        
        return {
            "index": entry.index,
            "hash": entry.hash
        }
    finally:
        db.close()

# Initialize database on import
init_db()
print("✅ Database initialized successfully")