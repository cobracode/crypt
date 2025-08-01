import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey
import base64
import os

# Constants
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # AES-256
ITERATIONS = 100_000

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Store salt + iv + ciphertext, all base64 encoded
    data = base64.b64encode(salt + iv + ciphertext).decode()
    return data

def decrypt(token: str, password: str) -> str:
    try:
        data = base64.b64decode(token)
        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
        ciphertext = data[SALT_SIZE+IV_SIZE:]
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
    except (ValueError, InvalidKey, Exception):
        raise ValueError("Decryption failed. Check your password and input.")

class CryptApp:
    def __init__(self, root):
        self.root = root
        root.title("Crypt - Text Encryptor/Decryptor")
        root.geometry("600x500")

        tk.Label(root, text="Enter text to encrypt/decrypt:").pack(anchor='w', padx=10, pady=(10,0))
        self.text_input = scrolledtext.ScrolledText(root, width=70, height=10)
        self.text_input.pack(padx=10, pady=5)

        tk.Label(root, text="Password:").pack(anchor='w', padx=10, pady=(10,0))
        self.password_entry = tk.Entry(root, show='*', width=40)
        self.password_entry.pack(padx=10, pady=5)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", command=self.encrypt_text, width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt", command=self.decrypt_text, width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", command=self.clear_fields, width=15).pack(side='left', padx=5)

        tk.Label(root, text="Output:").pack(anchor='w', padx=10, pady=(10,0))
        self.output = scrolledtext.ScrolledText(root, width=70, height=10, state='normal')
        self.output.pack(padx=10, pady=5)

    def encrypt_text(self):
        plaintext = self.text_input.get('1.0', tk.END).strip()
        password = self.password_entry.get()
        if not plaintext or not password:
            messagebox.showwarning("Input Required", "Please enter both text and password.")
            return
        try:
            encrypted = encrypt(plaintext, password)
            self.output.config(state='normal')
            self.output.delete('1.0', tk.END)
            self.output.insert(tk.END, encrypted)
            self.output.config(state='normal')
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_text(self):
        ciphertext = self.text_input.get('1.0', tk.END).strip()
        password = self.password_entry.get()
        if not ciphertext or not password:
            messagebox.showwarning("Input Required", "Please enter both encrypted text and password.")
            return
        try:
            decrypted = decrypt(ciphertext, password)
            self.output.config(state='normal')
            self.output.delete('1.0', tk.END)
            self.output.insert(tk.END, decrypted)
            self.output.config(state='normal')
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def clear_fields(self):
        self.password_entry.delete(0, tk.END)
        self.output.config(state='normal')
        self.output.delete('1.0', tk.END)
        self.output.config(state='normal')

def main():
    root = tk.Tk()
    app = CryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main() 