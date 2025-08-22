# file: vault.py
import sys
import os
import json
import base64
import getpass
import socket
from typing import Dict, Any, List, Tuple
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

# ========= FILE HELPERS =========
def read_all_bytes_from_file(path: str) -> bytes:
    f = open(path, "rb")
    try: data = f.read()
    finally:
        try: f.close()
        except Exception: pass
    return data

def write_all_bytes_to_file(path: str, data: bytes) -> None:
    f = open(path, "wb")
    try:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    finally:
        try: f.close()
        except Exception: pass

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# ========= ENCRYPTION =========
def derive_key_from_password_and_salt(password_bytes: bytes, salt_bytes: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=iterations, backend=default_backend())
    return kdf.derive(password_bytes)

def encrypt_vault_json_with_password(vault_json_text: str, password_text: str) -> bytes:
    salt = secrets.token_bytes(16)
    iterations = 200000
    key = derive_key_from_password_and_salt(password_text.encode(), salt, iterations)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, vault_json_text.encode(), None)
    obj = {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext)
    }
    return json.dumps(obj).encode()

def decrypt_vault_bytes_with_password(vault_bytes: bytes, password_text: str) -> str:
    obj = json.loads(vault_bytes.decode())
    iterations = int(obj["iterations"])
    salt_b = b64d(obj["salt"])
    nonce_b = b64d(obj["nonce"])
    ct_b = b64d(obj["ciphertext"])
    key = derive_key_from_password_and_salt(password_text.encode(), salt_b, iterations)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce_b, ct_b, None)
    return pt.decode()

# ========= DATA STRUCTURE =========
def initialize_new_vault_structure() -> Dict[str, Any]:
    return {"entries": [], "meta": {"created": int(secrets.randbits(32)), "version": 1}}

def vault_path_default() -> str:
    return str(Path(".").resolve() / "vault.enc")

def safe_input(prompt: str) -> str:
    try: return input(prompt)
    except (EOFError, KeyboardInterrupt): return ""

def safe_getpass(prompt: str) -> str:
    try: return getpass.getpass(prompt)
    except Exception: return ""

def load_or_create_vault(password_text: str, path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        raw = read_all_bytes_from_file(path)
        return json.loads(decrypt_vault_bytes_with_password(raw, password_text))
    else:
        obj = initialize_new_vault_structure()
        write_all_bytes_to_file(path, encrypt_vault_json_with_password(json.dumps(obj), password_text))
        return obj

def persist_vault(vault: Dict[str, Any], password_text: str, path: str) -> None:
    enc = encrypt_vault_json_with_password(json.dumps(vault), password_text)
    write_all_bytes_to_file(path, enc)

# ========= VAULT OPS =========
def list_entries(vault: Dict[str, Any]) -> List[Tuple[int, Dict[str, Any]]]:
    return list(enumerate(vault.get("entries", [])))

def add_contract_entry(vault: Dict[str, Any], name: str, addr: str) -> None:
    vault.setdefault("entries", []).append({"type": "contract", "name": name, "address": addr})

def add_wallet_entry(vault: Dict[str, Any], name: str, addr: str) -> None:
    vault.setdefault("entries", []).append({"type": "wallet", "name": name, "address": addr})

def search_entries(vault: Dict[str, Any], query: str) -> List[Tuple[int, Dict[str, Any]]]:
    results = []
    for i, e in enumerate(vault.get("entries", [])):
        if query.lower() in str(e.get("name", "")).lower() or query.lower() in str(e.get("address", "")).lower():
            results.append((i, e))
    return results

def delete_entry_at_index(vault: Dict[str, Any], idx: int) -> bool:
    try:
        vault["entries"].pop(idx)
        return True
    except Exception:
        return False

# ========= MENUS =========
def print_main_menu() -> None:
    print("==========================")
    print(" ENCRYPTED ADDRESS VAULT")
    print("==========================")
    print("[1] List Entries")
    print("[2] Add Contract")
    print("[3] Add Wallet")
    print("[4] Search")
    print("[5] Delete Entry")
    print("[6] Sync to Remote")
    print("[7] Pull from Remote")
    print("[8] Export Vault JSON")
    print("[9] Import Vault JSON")
    print("[h] Help")
    print("[0] Exit")
    print("--------------------------")

def print_help_menu() -> None:
    print("2 -> Add contract | 3 -> Add wallet | 4 -> Search | 5 -> Delete")
    print("6 -> Sync to Remote | 7 -> Pull from Remote")
    print("8 -> Export vault.json | 9 -> Import vault.json")
    print("0 -> Exit")

# ========= PROMPTS =========
def prompt_add_contract(v: Dict[str, Any]) -> None:
    add_contract_entry(v, safe_input("Contract name: "), safe_input("Contract address: "))

def prompt_add_wallet(v: Dict[str, Any]) -> None:
    add_wallet_entry(v, safe_input("Wallet name: "), safe_input("Wallet address: "))

def prompt_search(v: Dict[str, Any]) -> None:
    res = search_entries(v, safe_input("Search query: "))
    for idx, item in res:
        print(f"{idx} | {item['type']} | {item['name']} | {item['address']}")
    if not res: print("No results.")

def prompt_delete(v: Dict[str, Any]) -> None:
    try:
        idx = int(safe_input("Index to delete: "))
        print("Deleted." if delete_entry_at_index(v, idx) else "Invalid index.")
    except Exception:
        print("Invalid index.")

# ========= JSON IMPORT/EXPORT =========
def export_vault_json(vault: Dict[str, Any]) -> None:
    try:
        with open("vault.json", "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2, ensure_ascii=False)
        print("Exported vault.json (unencrypted).")
    except Exception as e:
        print("Export failed:", e)

def import_vault_json(vault: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with open("vault.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "entries" in data:
            print("Imported vault.json.")
            return data
        else:
            print("Invalid vault.json format.")
            return vault
    except Exception as e:
        print("Import failed:", e)
        return vault

# ========= REMOTE BACKENDS =========
def ftp_upload(local: str, host: str, user: str, pw: str, remote: str, port: int = 21) -> bool:
    try:
        ftp = FTP()
        ftp.connect(host, port)
        ftp.login(user, pw)
        with open(local, "rb") as f: ftp.storbinary(f"STOR {remote}", f)
        ftp.quit()
        return True
    except Exception: return False

def ftp_download(local: str, host: str, user: str, pw: str, remote: str, port: int = 21) -> bool:
    try:
        ftp = FTP()
        ftp.connect(host, port)
        ftp.login(user, pw)
        with open(local, "wb") as f: ftp.retrbinary(f"RETR {remote}", f.write)
        ftp.quit()
        return True
    except Exception: return False

def sftp_upload(local: str, host: str, user: str, pw: str, remote: str, port: int = 22) -> bool:
    if not paramiko: return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, pw)
        sftp = client.open_sftp()
        sftp.put(local, remote)
        sftp.close(); client.close()
        return True
    except Exception: return False

def sftp_download(local: str, host: str, user: str, pw: str, remote: str, port: int = 22) -> bool:
    if not paramiko: return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port, user, pw)
        sftp = client.open_sftp()
        sftp.get(remote, local)
        sftp.close(); client.close()
        return True
    except Exception: return False

def do_sync_to_remote(vault_path: str) -> None:
    backend = safe_input("Select backend (1=FTP,2=SFTP): ")
    if backend == "1":
        ok = ftp_upload(vault_path, safe_input("Host:"), safe_input("User:"), safe_getpass("Pass:"), safe_input("Remote:"))
        print("Synced." if ok else "Failed.")
    elif backend == "2":
        ok = sftp_upload(vault_path, safe_input("Host:"), safe_input("User:"), safe_getpass("Pass:"), safe_input("Remote:"))
        print("Synced." if ok else "Failed.")
    else: print("Cancelled.")

def do_pull_from_remote(vault_path: str) -> None:
    backend = safe_input("Select backend (1=FTP,2=SFTP): ")
    if backend == "1":
        ok = ftp_download(vault_path, safe_input("Host:"), safe_input("User:"), safe_getpass("Pass:"), safe_input("Remote:"))
        print("Pulled." if ok else "Failed.")
    elif backend == "2":
        ok = sftp_download(vault_path, safe_input("Host:"), safe_input("User:"), safe_getpass("Pass:"), safe_input("Remote:"))
        print("Pulled." if ok else "Failed.")
    else: print("Cancelled.")

# ========= PASSWORD =========
def ensure_password_for_existing_or_new(vault_file_path: str) -> str:
    if os.path.exists(vault_file_path):
        while True:
            p = safe_getpass("Master password: ")
            try:
                load_or_create_vault(p, vault_file_path)
                return p
            except Exception:
                print("Invalid password.")
    else:
        while True:
            p1 = safe_getpass("Set master password: ")
            p2 = safe_getpass("Confirm: ")
            if p1 == p2:
                write_all_bytes_to_file(vault_file_path, encrypt_vault_json_with_password(json.dumps(initialize_new_vault_structure()), p1))
                return p1
            else:
                print("Mismatch.")

# ========= MAIN LOOP =========
def main_loop() -> None:
    if "--help-menu" in sys.argv:
        print_main_menu(); return
    vault_file = vault_path_default()
    master_password = ensure_password_for_existing_or_new(vault_file)
    unlocked = load_or_create_vault(master_password, vault_file)
    while True:
        print_main_menu()
        choice = safe_input("Select: ")
        if choice == "1": 
            for i,e in list_entries(unlocked): print(f"{i} | {e['type']} | {e['name']} | {e['address']}")
        elif choice == "2": prompt_add_contract(unlocked); persist_vault(unlocked, master_password, vault_file)
        elif choice == "3": prompt_add_wallet(unlocked); persist_vault(unlocked, master_password, vault_file)
        elif choice == "4": prompt_search(unlocked)
        elif choice == "5": prompt_delete(unlocked); persist_vault(unlocked, master_password, vault_file)
        elif choice == "6": do_sync_to_remote(vault_file)
        elif choice == "7": do_pull_from_remote(vault_file)
        elif choice == "8": export_vault_json(unlocked)
        elif choice == "9": unlocked = import_vault_json(unlocked); persist_vault(unlocked, master_password, vault_file)
        elif choice.lower()=="h": print_help_menu()
        elif choice == "0": persist_vault(unlocked, master_password, vault_file); sys.exit(0)
        else: print("Invalid.")

if __name__ == "__main__":
    main_loop()
