# ADR 0008: Cryptographic Specification at Rest & AEAD AES-256 Migration Analysis

## Status
Accepted / Specification Corrected

## Context
In previous technical notes and phase summaries, the secret encryption mechanism utilized for SNMP device credentials (`auth_password`, `priv_password`, `snmp_community`) in `backend/app/services/snmp_service.py` was informally referenced as "AES-256 Fernet". 

An architectural and implementation audit was conducted prior to the Controlled Acceptance Test (UAT) to evaluate exact algorithm compliance, key derivation behavior, persistence guarantees, and future migration pathways.

---

## 1. Current Cryptographic Implementation Audit

### 1.1 Underlying Algorithm & Standard
The active implementation uses Python's standard `cryptography.fernet.Fernet` engine.
Under the official Fernet specification (RFC Fernet Format / PyCA Cryptography):
- **Cipher**: **AES-128 in Cipher Block Chaining (CBC) mode** with PKCS7 padding.
- **Integrity & Authentication**: **HMAC-SHA256** computed over the Version (1 byte), Timestamp (8 bytes), IV (16 bytes), and Ciphertext.
- **Key Structure**: A 32-byte (256-bit) raw key:
  - First 16 bytes: Used for HMAC-SHA256 signing and verification.
  - Second 16 bytes: Used for AES-128-CBC encryption.
- **Initialization Vector (IV)**: A cryptographically secure 128-bit random IV generated per encryption operation using `os.urandom(16)`.
- **Wire/Storage Format**: Base64 URL-safe encoded string starting with `gAAAAA...` (representing version byte `0x80` and 64-bit big-endian POSIX timestamp).

### 1.2 Key Derivation & Secret Key Persistence
The Fernet key is derived deterministically from the application's master `SECRET_KEY`:
```python
def _get_fernet_cipher() -> Fernet:
    raw_key = settings.SECRET_KEY.encode("utf-8")
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest())
    return Fernet(derived)
```
- **Properties**:
  - Deterministic and stateless: Derivation produces an identical 32-byte key upon every process restart, container redeployment, or worker fork.
  - Zero key loss: Encrypted credentials stored in PostgreSQL `snmp_profiles` remain 100% decipherable across restarts provided `SECRET_KEY` remains constant.
  - Isolation: Decryption failure (due to corrupted data or altered `SECRET_KEY`) is caught cleanly, logs an anonymous error, and returns `None` without leaking plaintexts or stack traces.

### 1.3 Key Storage & Environment File Protection
- `SECRET_KEY` is loaded strictly via Pydantic Settings from environment variables (`.env`).
- `.env` is explicitly ignored by version control in `.gitignore`.
- On production Linux deployments, `.env` file permissions must be restricted to `chmod 0600` owned by the non-privileged service user (`chown jdp:jdp .env`).

---

## 2. Documentation Corrections

All project documentation (`README.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_PLAN.md`, runbooks) is formally corrected:
- **Prior Incorrect Label**: "AES-256 Fernet" or "Fernet AES-256"
- **Accurate Authoritative Label**: **AES-128-CBC with HMAC-SHA256 Authenticated Encryption (Fernet Specification)**

---

## 3. AEAD AES-256 (AES-256-GCM) Migration Analysis

If enterprise compliance, defense-in-depth policies, or regulatory frameworks (such as FIPS 140-3 or NIST SP 800-38D) mandate true **256-bit symmetric encryption with Authenticated Encryption with Associated Data (AEAD)**, the following migration architecture is designed.

### 3.1 Proposed Target Algorithm
- **Algorithm**: **AES-256-GCM** (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
- **Key**: 32 bytes (256 bits) derived via HKDF-SHA256 or SHA-256 directly.
- **Nonce/IV**: 12 bytes (96 bits) unique per operation.
- **Tag**: 16 bytes (128 bits) authentication tag automatically verified during decryption.

### 3.2 Envelope Format & Backward Compatibility
To avoid breaking existing encrypted records, a versioned envelope prefix is established:

| Format | Identifying Prefix | Decryption Strategy |
|---|---|---|
| **Legacy Fernet** | `gAAAAA...` (or un-prefixed) | Decrypt with legacy Fernet cipher (AES-128-CBC + HMAC) |
| **New AEAD v1** | `$aead:v1:aes256gcm$` | Extract 12-byte IV, decrypt & verify tag via `AESGCM` |

### 3.3 Seamless Dual-Cipher Decrypt Logic
```python
def decrypt_snmp_secret(cipher_text: Optional[str]) -> Optional[str]:
    if not cipher_text:
        return None
    try:
        if cipher_text.startswith("$aead:v1:aes256gcm$"):
            raw_b64 = cipher_text[len("$aead:v1:aes256gcm$"):]
            payload = base64.urlsafe_b64decode(raw_b64.encode("utf-8"))
            nonce = payload[:12]
            ciphertext_with_tag = payload[12:]
            aesgcm = AESGCM(hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest())
            decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=b"jdp-snmp-credential")
            return decrypted.decode("utf-8")
        else:
            # Fallback to existing Fernet
            cipher = _get_fernet_cipher()
            decrypted = cipher.decrypt(cipher_text.encode("utf-8"))
            return decrypted.decode("utf-8")
    except Exception:
        logger.error("Failed to decrypt SNMP credential at rest")
        return None
```

### 3.4 Migration Execution Workflow
1. **Zero-Downtime Code Rollout**: Deploy the dual-cipher decryptor. The decryptor accepts both Fernet and AES-256-GCM records immediately.
2. **Batch Re-encryption**: Execute `scripts/migrate_snmp_secrets.py` to iterate through all rows in `snmp_profiles`, decrypt legacy Fernet strings, re-encrypt using AES-256-GCM, and save back to the database.
3. **Write Switch**: Update `encrypt_snmp_secret()` to write the new `$aead:v1:aes256gcm$` format for all subsequent user updates.
4. **Decommission**: Once all database rows are verified as `$aead:v1:`, legacy Fernet fallback can be removed in a future major release.

---

## 4. Operational Recommendations for UAT
- For current Phase 8 and Pre-UAT testing, the existing Fernet implementation remains active, stable, verified by unit tests (`test_snmp_secret_encryption_and_decryption`), and fully compatible with existing seeded database profiles.
- **DO NOT** rotate `SECRET_KEY` in `.env` without running a key rotation re-encryption drill, as changing `SECRET_KEY` without re-encryption would invalidate existing SNMP profile credentials.
