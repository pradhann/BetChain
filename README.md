# BetChain

A secure blockchain-based peer-to-peer betting system built with cryptographic signatures and hash-chained integrity.

## Features

- **Cryptographic Security**: Ed25519 digital signatures prevent impersonation
- **Blockchain Integrity**: Hash-chained transactions detect any tampering
- **Peer-to-Peer**: Direct betting between users without intermediaries
- **Tamper-Evident**: Append-only ledger with comprehensive validation
- **Modern UI**: Clean, professional interface with real-time updates

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Server

```bash
cd app
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Open the App

Navigate to: http://localhost:8000

## Getting Started

### First Time Setup

1. **Generate Keys**: Click "Generate New Keys" to create your cryptographic key pair
2. **Save Keys**: Copy and securely store your private key (you'll need it to login)
3. **Register**: Your public key is automatically registered with your username

### Using BetChain

1. **Login**: Enter your username and private key
2. **Propose Bet**: Create a new bet with terms and stake
3. **Accept Bets**: View and accept pending bets from other users
4. **Track History**: View all your betting activity in the chain

## Security Model

BetChain uses multiple layers of security:

### Cryptographic Authentication
- Each transaction signed with Ed25519 private key
- Public key verification prevents impersonation
- Client-side key management (server never sees private keys)

### Blockchain Integrity
- Hash-chained entries create tamper-evident audit trail
- Each entry links cryptographically to the previous
- Any modification breaks the chain and is detected

### Business Logic Validation
- Stakes cannot be zero, empty, or invalid
- Only counterparties can accept bets
- Comprehensive input validation and sanitization

### Append-Only Storage
- Transactions cannot be deleted or modified
- File locking prevents race conditions
- Immutable history of all betting activity

## API Endpoints

- `GET /` - Web interface
- `POST /register` - Register new user
- `GET /users` - List registered users  
- `POST /tx` - Submit new transaction
- `GET /chain` - View full blockchain
- `GET /bets` - View betting status
- `GET /verify` - Verify chain integrity

## File Structure

```
BetChain/
├── app/
│   ├── main.py           # FastAPI server
│   ├── models.py         # Data models
│   ├── chain.py          # Blockchain logic
│   ├── crypto.py         # Cryptographic functions
│   ├── static/
│   │   ├── index.html    # Main web interface
│   │   └── key-generator-simple.html  # Key generation tool
│   └── store/
│       ├── chain.jsonl   # Blockchain data
│       └── users.json    # Registered users
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Security Best Practices

### For Users
- **Keep Private Keys Secure**: Never share your private key
- **Use Strong Usernames**: Choose unique, memorable usernames
- **Verify Bets**: Always double-check bet terms before accepting
- **Regular Backups**: Consider backing up your private key safely

### For Deployment
- **HTTPS Only**: Always use SSL/TLS in production
- **Secure Storage**: Protect the `store/` directory
- **Regular Verification**: Periodically check `/verify` endpoint
- **Access Control**: Implement proper network security

## Production Deployment

### Environment Setup
```bash
# Install production ASGI server
pip install gunicorn

# Run with Gunicorn
cd app
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ /app/
WORKDIR /app
EXPOSE 8000
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

### Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Common Issues

**"Invalid signature" errors**
- Ensure private key matches registered public key
- Check that bet terms haven't changed during signing

**Chain verification fails**
- Stop the server and check `store/chain.jsonl` for corruption
- Restore from backup if available

**Login not working**
- Verify username is registered in `store/users.json`
- Ensure private key is correctly formatted (128 hex characters)

**Key generation fails**
- Use the simple key generator at `/key-generator-simple.html`
- Ensure browser supports Web Crypto API or use fallback

### Getting Help

1. Check the browser console for JavaScript errors
2. Check server logs for API errors
3. Verify chain integrity with `/verify` endpoint
4. Ensure all files in `store/` directory are writable

## Technical Details

### Cryptography
- **Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Format**: DER-encoded public keys, hex-encoded signatures
- **Hash Function**: SHA-256 for blockchain integrity

### Data Format
- **Storage**: JSONL (JSON Lines) for append-only blockchain
- **Encoding**: UTF-8 with canonical JSON serialization
- **Validation**: Pydantic models with comprehensive type checking

### Performance
- **Signature Verification**: ~1ms per transaction
- **Chain Validation**: Linear time complexity O(n)
- **Storage**: ~500 bytes per transaction on average

## License

This project is for educational and personal use. Please use responsibly and in accordance with local gambling laws.

---

**Built with**: FastAPI, Pydantic, Cryptography, HTML5, CSS3, JavaScript