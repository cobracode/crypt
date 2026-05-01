# Crypt

A simple Python GUI app to encrypt and decrypt text using password-based AES encryption.

## Features
- Multi-line text input
- Password-based encryption (AES-256, PBKDF2)
- Encrypt and Decrypt buttons
- Copy-paste text support

## Requirements
- Python 3.7+
- Tkinter (usually included with Python)
- cryptography

## Setup

Pre: activate the virtual environment. (Create it if it doesn't exist).
```bash
source .venv/bin/activate
```


1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the app:

```bash
python main.py
```

3. When finished, deactivate the virtual environment:
```bash
deactivate
```

## Usage
- Enter your text in the top box.
- Enter a password.
- Click **Encrypt** to encrypt, or **Decrypt** to decrypt.
- Copy/paste between the input and output boxes as needed.

---
**Security note:**
- Use a strong password. This app does not store or transmit your data or password. 
