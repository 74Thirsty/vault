# file: vault.py
import sys
import os
import json
import base64
import getpass
import socket
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from ftplib import FTP

try:
    import paramiko
except Exception:
    paramiko = None

try:
    from smb.SMBConnection import SMBConnection
except Exception:
    SMBConnection = None

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

def read_all_bytes_from_file(path: str) -> bytes:
    f = open(path, "rb")
    try:
        data = f.read()
    finally:
        try:
            f.close()
        except Exception:
            pass
    return data

def write_all_bytes_to_file(path: str, data: bytes) -> None:
    f = open(path, "wb")
    try:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    finally:
        try:
            f.close()
        except Exception:
            pass

def read_all_text_from_file(path: str) -> str:
    f = open(path, "r", encoding="utf-8")
    try:
        data = f.read()
    finally:
        try:
            f.close()
        except Exception:
            pass
    return data

def write_all_text_to_file(path: str, text: str) -> None:
    f = open(path, "w", encoding="utf-8")
    try:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    finally:
        try:
            f.close()
        except Exception:
            pass

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_key_from_password_and_salt(password_bytes: bytes, salt_bytes: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=iterations, backend=default_backend())
    key = kdf.derive(password_bytes)
    return key

def encrypt_vault_json_with_password(vault_json_text: str, password_text: str) -> bytes:
    salt = secrets.token_bytes(16)
    iterations = 200000
    password_bytes = password_text.encode("utf-8")
    key = derive_key_from_password_and_salt(password_bytes, salt, iterations)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    plaintext_bytes = vault_json_text.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    obj = {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext)
    }
    encoded = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    for i in range(len(password_bytes)):
        password_bytes = b""
    key = b""
    plaintext_bytes = b""
    return encoded

def decrypt_vault_bytes_with_password(vault_bytes: bytes, password_text: str) -> str:
    obj = json.loads(vault_bytes.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("invalid")
    iterations = int(obj.get("iterations"))
    salt_b = b64d(str(obj.get("salt")))
    nonce_b = b64d(str(obj.get("nonce")))
    ct_b = b64d(str(obj.get("ciphertext")))
    password_bytes = password_text.encode("utf-8")
    key = derive_key_from_password_and_salt(password_bytes, salt_b, iterations)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce_b, ct_b, None)
    text = pt.decode("utf-8")
    for i in range(len(password_bytes)):
        password_bytes = b""
    key = b""
    pt = b""
    return text

def initialize_new_vault_structure() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data["entries"] = []
    data["meta"] = {}
    data["meta"]["created"] = int(secrets.randbits(32))
    data["meta"]["version"] = 1
    return data

def vault_path_default() -> str:
    return str(Path(".").resolve() / "vault.enc")

def safe_input(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""
    except KeyboardInterrupt:
        return ""

def safe_getpass(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except Exception:
        return ""

def load_or_create_vault(password_text: str, path: str) -> Dict[str, Any]:
    if os.path.exists(p
