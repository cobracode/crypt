import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey
import base64
import os
import threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256

# Constants
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # AES-256
ITERATIONS = 100_000
CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming

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
    """Encrypt text using AES-GCM for authenticated encryption."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AESGCM(key)
    nonce = os.urandom(12)  # GCM uses 12-byte nonce
    
    # Encrypt with authentication
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    
    # Store salt + nonce + ciphertext, all base64 encoded
    data = base64.b64encode(salt + nonce + ciphertext).decode()
    return data

def decrypt(token: str, password: str) -> str:
    """Decrypt text using AES-GCM for authenticated decryption."""
    try:
        data = base64.b64decode(token)
        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE+12]  # GCM uses 12-byte nonce
        ciphertext = data[SALT_SIZE+12:]
        
        key = derive_key(password, salt)
        cipher = AESGCM(key)
        
        # Decrypt with authentication
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except (ValueError, InvalidKey, Exception):
        raise ValueError("Decryption failed. Check your password and input.")

def encrypt_file(input_path: str, output_path: str, password: str, progress_callback=None) -> None:
    """Encrypt a file with hybrid approach: AES-GCM for small files, streaming HMAC for large files."""
    file_size = os.path.getsize(input_path)
    
    # For small files (< 10MB), use AES-GCM
    if file_size < 10 * 1024 * 1024:
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        cipher = AESGCM(key)
        nonce = os.urandom(12)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write salt and nonce at the beginning
            outfile.write(salt + nonce)
            plaintext = infile.read()
            ciphertext = cipher.encrypt(nonce, plaintext, None)
            outfile.write(ciphertext)
            
        if progress_callback:
            progress_callback(100)
    
    # For large files, use streaming with HMAC
    else:
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key = derive_key(password, salt)
        
        # Split key for encryption and authentication
        enc_key = key[:16]
        auth_key = key[16:]
        
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        h = hmac.HMAC(auth_key, SHA256(), backend=backend)
        
        processed = 0
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write salt and IV
            outfile.write(salt + iv)
            
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # Pad the last chunk if needed
                if len(chunk) < CHUNK_SIZE:
                    chunk = padder.update(chunk) + padder.finalize()
                else:
                    chunk = padder.update(chunk)
                
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)
                h.update(encrypted_chunk)  # Update HMAC
                
                processed += len(chunk)
                if progress_callback:
                    progress = (processed / file_size) * 100
                    progress_callback(progress)
            
            # Finalize encryption
            final_chunk = encryptor.finalize()
            if final_chunk:
                outfile.write(final_chunk)
                h.update(final_chunk)
            
            # Write HMAC tag
            tag = h.finalize()
            outfile.write(tag)

def decrypt_file(input_path: str, output_path: str, password: str, progress_callback=None) -> None:
    """Decrypt a file with hybrid approach: AES-GCM for small files, streaming HMAC for large files."""
    with open(input_path, 'rb') as infile:
        # Read salt to determine file format
        salt = infile.read(SALT_SIZE)
        
        # Check if this is a GCM file (12-byte nonce) or CBC file (16-byte IV)
        next_bytes = infile.read(16)
        infile.seek(SALT_SIZE)  # Reset position
        
        # Try to detect format based on file size and header
        file_size = os.path.getsize(input_path)
        header_size = SALT_SIZE + 12  # GCM header
        if file_size > header_size + 32:  # Minimum size for GCM
            try:
                # Try GCM first
                nonce = infile.read(12)
                key = derive_key(password, salt)
                cipher = AESGCM(key)
                
                # Read encrypted data
                ciphertext = infile.read()
                
                try:
                    # Decrypt with GCM authentication
                    plaintext = cipher.decrypt(nonce, ciphertext, None)
                    
                    with open(output_path, 'wb') as outfile:
                        outfile.write(plaintext)
                        
                    if progress_callback:
                        progress_callback(100)
                    return
                        
                except Exception:
                    # GCM failed, try CBC
                    pass
            except Exception:
                pass
        
        # Fall back to CBC/HMAC
        infile.seek(SALT_SIZE)
        iv = infile.read(IV_SIZE)
        
        key = derive_key(password, salt)
        enc_key = key[:16]
        auth_key = key[16:]
        
        # Read file to get HMAC tag
        ciphertext_size = file_size - SALT_SIZE - IV_SIZE - 32  # 32 bytes for HMAC
        
        # Read ciphertext and HMAC tag
        ciphertext = infile.read(ciphertext_size)
        tag = infile.read(32)
        
        # Verify HMAC
        h = hmac.HMAC(auth_key, SHA256(), backend=backend)
        h.update(ciphertext)
        try:
            h.verify(tag)
        except Exception:
            raise ValueError("File has been tampered with or password is incorrect")
        
        # Decrypt with streaming
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        processed = SALT_SIZE + IV_SIZE
        
        with open(output_path, 'wb') as outfile:
            # Process ciphertext in chunks
            chunk_size = CHUNK_SIZE
            for i in range(0, len(ciphertext), chunk_size):
                chunk = ciphertext[i:i + chunk_size]
                decrypted_chunk = decryptor.update(chunk)
                outfile.write(decrypted_chunk)
                
                processed += len(chunk)
                if progress_callback:
                    progress = (processed / file_size) * 100
                    progress_callback(progress)
            
            # Finalize decryption
            final_chunk = decryptor.finalize()
            if final_chunk:
                outfile.write(final_chunk)
            
            # Remove padding
            outfile.seek(0)
            content = outfile.read()
            outfile.seek(0)
            outfile.truncate()
            
            try:
                unpadded_content = unpadder.update(content) + unpadder.finalize()
                outfile.write(unpadded_content)
            except Exception:
                raise ValueError("Incorrect password or corrupted file")

class CryptApp:
    def __init__(self, root):
        self.root = root
        root.title("Crypt - Text & File Encryptor/Decryptor")
        root.geometry("700x600")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Text tab
        self.text_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.text_frame, text="Text")
        self.setup_text_tab()
        
        # File tab
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="Files")
        self.setup_file_tab()

    def setup_text_tab(self):
        tk.Label(self.text_frame, text="Enter text to encrypt/decrypt:").pack(anchor='w', padx=10, pady=(10,0))
        self.text_input = scrolledtext.ScrolledText(self.text_frame, width=70, height=10)
        self.text_input.pack(padx=10, pady=5)

        tk.Label(self.text_frame, text="Password:").pack(anchor='w', padx=10, pady=(10,0))
        self.password_entry = tk.Entry(self.text_frame, show='*', width=40)
        self.password_entry.pack(padx=10, pady=5)

        btn_frame = tk.Frame(self.text_frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", command=self.encrypt_text, width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt", command=self.decrypt_text, width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", command=self.clear_fields, width=15).pack(side='left', padx=5)

        tk.Label(self.text_frame, text="Output:").pack(anchor='w', padx=10, pady=(10,0))
        self.output = scrolledtext.ScrolledText(self.text_frame, width=70, height=10, state='normal')
        self.output.pack(padx=10, pady=5)

    def setup_file_tab(self):
        # File selection
        file_frame = tk.Frame(self.file_frame)
        file_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(file_frame, text="Input File:").pack(anchor='w')
        input_frame = tk.Frame(file_frame)
        input_frame.pack(fill='x', pady=5)
        self.file_path_var = tk.StringVar()
        tk.Entry(input_frame, textvariable=self.file_path_var, width=50).pack(side='left', fill='x', expand=True)
        tk.Button(input_frame, text="Browse", command=self.browse_file).pack(side='right', padx=(5,0))
        
        # Password
        tk.Label(self.file_frame, text="Password:").pack(anchor='w', padx=10, pady=(10,0))
        self.file_password_entry = tk.Entry(self.file_frame, show='*', width=40)
        self.file_password_entry.pack(padx=10, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(self.file_frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt File", command=self.encrypt_file, width=15).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file, width=15).pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.file_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=10, pady=10)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        tk.Label(self.file_frame, textvariable=self.status_var).pack(pady=5)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)

    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def encrypt_file(self):
        input_path = self.file_path_var.get()
        password = self.file_password_entry.get()
        
        if not input_path or not password:
            messagebox.showwarning("Input Required", "Please select a file and enter a password.")
            return
        
        if not os.path.exists(input_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        # Generate output path
        input_file = Path(input_path)
        output_path = str(input_file.parent / f"{input_file.stem}_encrypted{input_file.suffix}")
        
        # Check if output file already exists and ask for confirmation
        if os.path.exists(output_path):
            response = messagebox.askyesno(
                "File Exists", 
                f"Output file already exists:\n{output_path}\n\nDo you want to overwrite it?"
            )
            if not response:
                return
        
        def encrypt_worker():
            try:
                self.update_status("Encrypting file...")
                encrypt_file(input_path, output_path, password, self.update_progress)
                self.update_status("Encryption completed!")
                self.progress_var.set(100)
                messagebox.showinfo("Success", f"File encrypted successfully!\nSaved to: {output_path}")
            except Exception as e:
                self.update_status("Encryption failed!")
                messagebox.showerror("Encryption Error", str(e))
            finally:
                self.progress_var.set(0)
        
        # Run in separate thread to avoid blocking UI
        threading.Thread(target=encrypt_worker, daemon=True).start()

    def decrypt_file(self):
        input_path = self.file_path_var.get()
        password = self.file_password_entry.get()
        
        if not input_path or not password:
            messagebox.showwarning("Input Required", "Please select a file and enter a password.")
            return
        
        if not os.path.exists(input_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        # Generate output path
        input_file = Path(input_path)
        if input_file.stem.endswith('_encrypted'):
            output_name = input_file.stem[:-10]  # Remove '_encrypted'
        # else:
        #     output_name = f"{input_file.stem}_decrypted"
        output_path = str(input_file.parent / f"{output_name}_decrypted{input_file.suffix}")
        
        # Check if output file already exists and ask for confirmation
        if os.path.exists(output_path):
            response = messagebox.askyesno(
                "File Exists", 
                f"Output file already exists:\n{output_path}\n\nDo you want to overwrite it?"
            )
            if not response:
                return
        
        def decrypt_worker():
            try:
                self.update_status("Decrypting file...")
                decrypt_file(input_path, output_path, password, self.update_progress)
                self.update_status("Decryption completed!")
                self.progress_var.set(100)
                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved to: {output_path}")
            except Exception as e:
                self.update_status("Decryption failed!")
                messagebox.showerror("Decryption Error", str(e))
            finally:
                self.progress_var.set(0)
        
        # Run in separate thread to avoid blocking UI
        threading.Thread(target=decrypt_worker, daemon=True).start()

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

    # # Force proper initialization for debugger
    # root.update_idletasks()
    # root.deiconify()
    # root.lift()
    # root.focus_force()

    app = CryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()