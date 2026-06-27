import base64
import logging
import threading

logger = logging.getLogger(__name__)

# Windows DPAPI support (optional)
try:
    import win32crypt
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False
    logger.info("pywin32 not installed; DPAPI persistence disabled (memory-only mode)")


# Session-only credentials (in-memory, cleared immediately after collection)
# HARDENING (CWE-522): Credentials are cleared as soon as collection completes, not persisted in memory
# M5 (CWE-362): A lock guards _session so request and worker threads cannot race
# on the same switch_id during the async credential lifecycle.
_session = {}
_session_lock = threading.Lock()


def save_credential(switch_id, username, password, persist=False):
    """Save credentials to session memory or DPAPI-encrypted DB.

    Args:
        switch_id: Switch ID
        username: SSH username
        password: SSH password
        persist: If True, encrypt with DPAPI and save to DB (requires Windows)

    Returns:
        dict with 'ok' status and optional 'encrypted' flag
    """
    with _session_lock:
        _session[switch_id] = {"username": username, "password": password}

    result = {"ok": True, "encrypted": False}

    # DPAPI encryption for persistent storage
    if persist and IS_WINDOWS:
        try:
            encrypted_data = encrypt_credential(username, password)
            if encrypted_data:
                # Caller (app.py or collector.py) must handle DB update
                result["encrypted"] = True
                result["cred_blob"] = encrypted_data
                logger.info(f"[DPAPI] Credential encrypted for switch {switch_id}")
        except Exception as e:
            logger.warning(f"[DPAPI] Encryption failed: {e}; falling back to session-only")

    return result


def load_credential(switch_id):
    """Load credentials from session memory for the specific switch.

    HARDENING (CWE-522): No fallback to last-used credentials; only return switch-specific session credentials.
    M5 (CWE-522): Returns a defensive COPY so callers can zeroize their copy
    without mutating the session store.
    Returns:
        dict with 'username' and 'password', or None if not found for this switch
    """
    with _session_lock:
        cred = _session.get(switch_id)
        cred_copy = dict(cred) if cred else None
    if cred_copy:
        logger.info(f"Credential loaded from session for switch {switch_id}")
        return cred_copy

    logger.warning(f"No session credential found for switch {switch_id}")
    return None


def clear_session_switch(switch_id):
    """Clear session credentials for a specific switch immediately after collection.

    HARDENING (CWE-522): Remove plaintext credentials from memory as soon as possible.
    """
    with _session_lock:
        if switch_id in _session:
            del _session[switch_id]
            logger.info(f"Session credentials cleared for switch {switch_id}")


def clear_session():
    """Clear all session credentials (e.g., on app shutdown)."""
    with _session_lock:
        _session.clear()
    logger.info("All session credentials cleared")


def encrypt_credential(username, password):
    """Encrypt username:password with Windows DPAPI.

    Args:
        username: SSH username
        password: SSH password

    Returns:
        base64-encoded encrypted blob, or None if encryption fails
    """
    if not IS_WINDOWS:
        return None

    try:
        plaintext = f"{username}|{password}"
        encrypted_bytes = win32crypt.CryptProtectData(plaintext.encode("utf-8"), None, None, None, None, 0x01)
        cred_blob = base64.b64encode(encrypted_bytes).decode("ascii")
        return cred_blob
    except Exception as e:
        logger.error(f"[DPAPI] Encryption error: {e}")
        return None


def decrypt_credential(cred_blob):
    """Decrypt DPAPI blob back to plaintext.

    Args:
        cred_blob: base64-encoded encrypted data

    Returns:
        plaintext string (username|password), or None if decryption fails
    """
    if not IS_WINDOWS or not cred_blob:
        return None

    try:
        encrypted_bytes = base64.b64decode(cred_blob)
        decrypted_bytes = win32crypt.CryptUnprotectData(encrypted_bytes, None, None, None, 0)
        plaintext = decrypted_bytes[0].decode("utf-8")
        return plaintext
    except Exception as e:
        logger.error(f"[DPAPI] Decryption error: {e}")
        return None


