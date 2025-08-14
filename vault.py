#!/usr/bin/env python3
import os
import io
import json
import base64
import getpass
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import paramiko
from ftplib import FTP
import argparse
try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    SMBConnection = None

# ===== CONFIG =====
LOCAL_VAULT_PATH = Path("vault.enc")  # default local vault
ITERATIONS = 390000

# ===== Encryption Core =====
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_vault(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    encrypted = Fernet(key).encrypt(json.dumps(data).encode())
    return salt + encrypted

def decrypt_vault(blob, password):
    salt, encrypted = blob[:16], blob[16:]
    key = derive_key(password, salt)
    decrypted = Fernet(key).decrypt(encrypted)
    return json.loads(decrypted)

# ===== Storage Backends =====
def save_local(path, blob):
    Path(path).write_bytes(blob)

def load_local(path):
    return Path(path).read_bytes()

def save_ftp(host, user, pwd, path, blob):
    ftp = FTP(host)
    ftp.login(user, pwd)
    ftp.storbinary(f'STOR {path}', io.BytesIO(blob))
    ftp.quit()

def load_ftp(host, user, pwd, path):
    ftp = FTP(host)
    ftp.login(user, pwd)
    bio = io.BytesIO()
    ftp.retrbinary(f'RETR {path}', bio.write)
    ftp.quit()
    return bio.getvalue()

def save_sftp(host, user, pwd, path, blob):
    transport = paramiko.Transport((host, 22))
    transport.connect(username=user, password=pwd)
    sftp = paramiko.SFTPClient.from_transport(transport)
    with sftp.file(path, 'wb') as f:
        f.write(blob)
    sftp.close()
    transport.close()

def load_sftp(host, user, pwd, path):
    transport = paramiko.Transport((host, 22))
    transport.connect(username=user, password=pwd)
    sftp = paramiko.SFTPClient.from_transport(transport)
    with sftp.file(path, 'rb') as f:
        data = f.read()
    sftp.close()
    transport.close()
    return data

def save_smb(server, share, path, user, pwd):
    if SMBConnection is None:
        print("SMB support not installed. Run: pip install pysmb")
        return
    conn = SMBConnection(user, pwd, "vault-client", "vault-server", use_ntlm_v2=True)
    assert conn.connect(server, 139)
    with open(path, 'rb') as f:
        conn.storeFile(share, os.path.basename(path), f)
    conn.close()

# ===== Vault Actions =====
def init_vault(password):
    data = {"contracts": {}, "wallets": {}}
    save_local(LOCAL_VAULT_PATH, encrypt_vault(data, password))
    print(f"Vault created at {LOCAL_VAULT_PATH}")

def load_vault(password):
    blob = load_local(LOCAL_VAULT_PATH)
    return decrypt_vault(blob, password)

def save_vault(data, password):
    save_local(LOCAL_VAULT_PATH, encrypt_vault(data, password))

def list_entries(data):
    print(json.dumps(data, indent=2))

def add_entry(data, entry_type):
    name = input(f"{entry_type} name: ").strip()
    addr = input("Address: ").strip()
    data[entry_type + "s"][name] = addr
    print(f"Added {entry_type}: {name} → {addr}")

def search_entries(data):
    query = input("Search term: ").strip().lower()
    results = []
    for t in ["contracts", "wallets"]:
        for k, v in data[t].items():
            if query in k.lower() or query in v.lower():
                results.append((t, k, v))
    if results:
        for t, k, v in results:
            print(f"[{t}] {k}: {v}")
    else:
        print("No matches found.")

def delete_entry(data):
    t = input("Type (contract/wallet): ").strip().lower() + "s"
    name = input("Name to delete: ").strip()
    if name in data[t]:
        del data[t][name]
        print(f"Deleted {t[:-1]}: {name}")
    else:
        print("Entry not found.")

# ===== Help =====
def help_menu():
    print("""
Encrypted Address Vault - Help
==============================
[1] List Entries     - Show all stored wallets/contracts.
[2] Add Contract     - Add a named contract address.
[3] Add Wallet       - Add a named wallet address.
[4] Search           - Search by name or address.
[5] Delete Entry     - Remove a wallet or contract from vault.
[6] Sync to Remote   - Upload encrypted vault to FTP/SFTP/SMB.
[7] Pull from Remote - Download encrypted vault from FTP/SFTP.
[0] Exit             - Save and quit.
""")

# ===== Interactive Menu =====
def main_menu():
    print("""
==========================
 ENCRYPTED ADDRESS VAULT
==========================
[1] List Entries
[2] Add Contract
[3] Add Wallet
[4] Search
[5] Delete Entry
[6] Sync to Remote
[7] Pull from Remote
[h] Help
[0] Exit
--------------------------
""")

# ===== Main =====
def main():
    parser = argparse.ArgumentParser(description="Encrypted Address Vault CLI")
    parser.add_argument("--help-menu", action="store_true", help="Show help and exit")
    args = parser.parse_args()

    if args.help_menu:
        help_menu()
        return

    if not LOCAL_VAULT_PATH.exists():
        pwd = getpass.getpass("Set master password: ")
        init_vault(pwd)

    pwd = getpass.getpass("Enter master password: ")
    data = load_vault(pwd)

    while True:
        main_menu()
        choice = input("> ").strip().lower()
        if choice == "1":
            list_entries(data)
        elif choice == "2":
            add_entry(data, "contract")
        elif choice == "3":
            add_entry(data, "wallet")
        elif choice == "4":
            search_entries(data)
        elif choice == "5":
            delete_entry(data)
        elif choice == "6":
            print("Choose backend: [1] FTP  [2] SFTP  [3] SMB")
            b = input("> ").strip()
            blob = encrypt_vault(data, pwd)
            if b == "1":
                h = input("FTP host: "); u = input("User: "); pw = getpass.getpass("Password: "); p = input("Remote path: ")
                save_ftp(h, u, pw, p, blob)
            elif b == "2":
                h = input("SFTP host: "); u = input("User: "); pw = getpass.getpass("Password: "); p = input("Remote path: ")
                save_sftp(h, u, pw, p, blob)
            elif b == "3":
                if SMBConnection is None:
                    print("SMB not available. pip install pysmb")
                else:
                    srv = input("SMB server: "); share = input("Share name: "); u = input("User: "); pw = getpass.getpass("Password: ")
                    save_smb(srv, share, str(LOCAL_VAULT_PATH), u, pw)
        elif choice == "7":
            print("Choose backend: [1] FTP  [2] SFTP")
            b = input("> ").strip()
            if b == "1":
                h = input("FTP host: "); u = input("User: "); pw = getpass.getpass("Password: "); p = input("Remote path: ")
                blob = load_ftp(h, u, pw, p); data = decrypt_vault(blob, pwd)
            elif b == "2":
                h = input("SFTP host: "); u = input("User: "); pw = getpass.getpass("Password: "); p = input("Remote path: ")
                blob = load_sftp(h, u, pw, p); data = decrypt_vault(blob, pwd)
        elif choice == "h":
            help_menu()
        elif choice == "0":
            save_vault(data, pwd)
            break

if __name__ == "__main__":
    main()
