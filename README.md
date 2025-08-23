
# 🔐 Encrypted Address Vault CLI

![GADGET SAAVY banner](https://raw.githubusercontent.com/74Thirsty/74Thirsty/main/assets/banner.svg)

## 🔧 Technologies & Tools

[![Cyfrin](https://img.shields.io/badge/Cyfrin-Audit%20Ready-005030?logo=shield&labelColor=F47321)](https://www.cyfrin.io/)
[![FlashBots](https://img.shields.io/pypi/v/finta?label=Finta&logo=python&logoColor=2774AE&labelColor=FFD100)](https://www.flashbots.net/)
[![Python](https://img.shields.io/badge/Python-3.11-003057?logo=python&labelColor=B3A369)](https://www.python.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-7BAFD4?logo=ethereum&labelColor=4B9CD3)](https://docs.soliditylang.org)
[![pYcHARM](https://img.shields.io/badge/Built%20with-PyCharm-782F40?logo=pycharm&logoColor=CEB888)](https://www.jetbrains.com/pycharm/)
[![Issues](https://img.shields.io/github/issues/74Thirsty/vault.svg?color=hotpink&labelColor=brightgreen)](https://github.com/74Thirsty/vault/issues)
[![Lead Dev](https://img.shields.io/badge/C.Hirschauer-Lead%20Developer-041E42?logo=parrotsecurity&labelColor=C5B783)](https://christopherhirschauer.bio)
[![Security](https://img.shields.io/badge/encryption-AES--256-orange.svg?color=13B5EA&labelColor=9EA2A2)]()

> <p><strong>Christopher Hirschauer</strong><br>
> Builder @ the bleeding edge of MEV, automation, and high-speed arbitrage.<br>
<em>June 13, 2025</em></p>

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

This project is released under the **Gadget Saavy Vault Script License**.  
See the full license text here: [LICENSE.md](./LICENSE.md)


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
vault.salt
```
