
# 🔐 Encrypted Address Vault CLI

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ethereum](https://img.shields.io/badge/network-Ethereum-%236C71C4)](https://ethereum.org/)
[![Security](https://img.shields.io/badge/encryption-AES--256-orange.svg)]()
[![Issues](https://img.shields.io/github/issues/74Thirsty/vault.svg)](https://github.com/74Thirsty/vault/issues)

A cross-platform, interactive command-line tool for securely storing and managing **wallet addresses** and **contract addresses** — encrypted locally with AES-256 and syncable to remote backends like **FTP**, **SFTP**, and **SMB**.

This tool ensures your sensitive blockchain data never leaves your machine **unencrypted**, and your master password is **never stored** anywhere.

---

## ✨ Features

- **AES-256 Encryption** with PBKDF2 key derivation
- **Global Master Password** — one password unlocks the entire vault
- **Interactive Menu** — no remembering complex commands
- **Multi-backend Sync**:
  - Local file storage
  - FTP upload/download
  - SFTP upload/download
  - SMB/CIFS upload (if `pysmb` is installed)
- **Search, Add, Delete** entries easily
- **Cross-platform** (Linux, macOS, Windows)
- Works **offline**, sync optional
- CLI **help menu** (`--help-menu`) + in-menu help (`h`)

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone git@github.com:<your-username>/<repo-name>.git
cd <repo-name>
````

### 2. Install dependencies

```bash
pip install cryptography paramiko pysmb
```

> `pysmb` is only needed if you want SMB support.

---

## 🚀 Usage

### Start the vault

```bash
python vault.py
```

On first run:

* You will be prompted to **set a master password**
* A new encrypted vault file `vault.enc` will be created locally

---

### Main Menu

```
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
```

**Example:**

* `2` → Add a contract (name + address)
* `4` → Search by name or partial address
* `6` → Push vault to FTP/SFTP/SMB
* `h` → Show help

---

### CLI Help

```bash
python vault.py --help-menu
```

---

## 🌐 Remote Sync Examples

### Push to FTP

Select **Sync to Remote** → `1` for FTP
Enter:

* Host: `ftp.example.com`
* Username/Password
* Remote Path: `/backup/vault.enc`

### Push to SFTP

Select **Sync to Remote** → `2` for SFTP
Enter:

* Host: `sftp.example.com`
* Username/Password
* Remote Path: `/secure/vault.enc`

### Push to SMB

Select **Sync to Remote** → `3` for SMB
Requires:

```bash
pip install pysmb
```

---

## 🔒 Security

* **No master password storage**
* Vault file (`vault.enc`) is **AES-256 encrypted** before any transfer
* Remote storage (FTP/SFTP/SMB) only sees encrypted binary data
* If you lose your password, your vault **cannot** be recovered

---

## 🛠 Requirements

* Python 3.8+
* `cryptography` for AES encryption
* `paramiko` for SFTP
* `pysmb` for SMB (optional)

Install all at once:

```bash
pip install cryptography paramiko pysmb
```

---

## 📄 License

MIT License — feel free to fork, modify, and contribute.

---

## 💡 Future Plans

* WebDAV backend
* Encrypted backend profiles (no retyping host/user/pass)
* Packaging as standalone EXE/APP

---

### 🚧 Disclaimer

**Never** commit your live `vault.enc` to a public repository.
Add it to `.gitignore`:

```
vault.enc
```

```

