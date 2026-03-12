# EncryptionApp v2

A desktop application for **AES-256-GCM encryption** of files, text, and passwords — entirely local, no network access, no cloud.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **File Encryption** — Chunked AES-256-GCM encryption for files of any size, with a live progress bar and mid-operation cancellation.
- **Text Encryption** — Encrypt and decrypt arbitrary text in memory; export/import as `.etxt` (JSON) files.
- **Password Vault** — An encrypted local vault (`~/.encryptionapp_vault.json`) to securely store usernames, passwords, and notes.
- **Key Management** — Generate or load 256-bit `.key` files; verify keys via their SHA-256 fingerprint.
- **Dual Key Modes** — All encryption operations accept either a **password** (Scrypt KDF-derived key) or a **raw key file**.
- **Global Key State** — A key loaded in Key Management is shared across all pages.
- **Light / Dark Theme** — Toggle from the sidebar; dark mode by default.
- **Responsive UI** — File operations run on background threads; the interface never freezes.

---

## Security

| Primitive | Details |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| KDF (files/text) | Scrypt — N=2¹⁷, r=8, p=1 (OWASP 2024 minimum) |
| KDF (vault) | PBKDF2-SHA256 — 600 000 iterations (NIST SP 800-132) |
| Nonce | 96-bit random nonce, freshly generated per operation |
| Salt | 256-bit random salt, stored alongside ciphertext |
| Chunk auth | Each 64 KB chunk is independently authenticated |

Every ciphertext is validated before any plaintext is written. Truncated or tampered files are rejected outright.

---

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`:

```
cryptography >= 41.0.0
customtkinter >= 5.2.0
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/EncryptionApp-v2.git
cd EncryptionApp-v2

# 2. (Recommended) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python main.py
```

---

## Usage

### File Encryption / Decryption
1. Navigate to the **File** page from the sidebar.
2. Select the file you want to encrypt or decrypt.
3. Choose a key source — enter a **password** or load a **key file**.
4. Click **Encrypt** or **Decrypt**. Progress is shown in the status bar.

### Text Encryption / Decryption
1. Navigate to the **Text** page.
2. Paste or type the plaintext in the input box.
3. Choose a password or key file and click **Encrypt**.
4. Optionally export the result as a `.etxt` file or copy it to the clipboard.

### Key Management
1. Navigate to the **Keys** page.
2. Click **Generate Key** to create a new 256-bit key file, or **Load Key** to import an existing one.
3. The SHA-256 fingerprint is displayed for verification.
4. The loaded key is automatically available on the File and Text pages.

### Password Vault
1. Navigate to the **Vault** page.
2. Create a new vault with a master password, or unlock an existing one.
3. Add, view, copy, or delete entries (service name, username, password, notes).
4. Click **Lock** to wipe the master key from memory.

---

## Project Structure

```
EncryptionApp-v2/
├── main.py                        # Entry point
├── requirements.txt
├── app/
│   ├── config.py                  # Constants and configuration
│   ├── crypto/
│   │   ├── core.py                # AES-256-GCM primitives
│   │   ├── kdf.py                 # Scrypt and PBKDF2 key derivation
│   │   └── file_crypto.py         # Chunked file encryption
│   ├── vault/
│   │   └── password_vault.py      # Encrypted password vault
│   └── gui/
│       ├── app_window.py          # Main window and navigation
│       ├── status_bar.py          # Bottom status bar
│       ├── task_reporter.py       # Thread → UI progress bridge
│       ├── widgets.py             # Shared UI helpers
│       ├── pages/
│       │   ├── file_page.py
│       │   ├── text_page.py
│       │   ├── key_page.py
│       │   └── vault_page.py
│       └── dialogs/
│           └── vault_entry_dialog.py
```

---

## License

This project is licensed under the [GNU GPLv3](LICENSE).
