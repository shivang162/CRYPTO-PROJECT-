import customtkinter as ctk # type: ignore
from tkinter import filedialog, messagebox
import os
import time

# Import cryptography libraries for AES-GCM and PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# App Window Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("🔒 Secure File Encryption & Decryption Tool")
app.geometry("720x500")

# ----- CRYPTO CONSTANTS (must match C++ values) -----
KEY_SIZE = 32         # 256 bits
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100_000
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16

def validate_password_strength(password):
    """Validate password meets minimum security requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        return True, "Warning: Weak password. Consider using uppercase, lowercase, and numbers"
    
    return True, None

def derive_key(password, salt):
    """Derive AES-256 key from password and salt using PBKDF2-SHA256."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    except Exception as e:
        raise ValueError(f"Key derivation failed: {str(e)}")

def encrypt_file_compatible(input_path, output_path, password):
    """Encrypt file using AES-256-GCM and write [salt][iv][tag][ciphertext] to output_path."""
    try:
        # Check if input file exists
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read plaintext
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Allow empty files but warn user
        if len(plaintext) == 0:
            print("Warning: Input file is empty")

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        iv = os.urandom(GCM_IV_SIZE)

        encryptor = Cipher(
            algorithms.AES(key), 
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(tag)
            f.write(ciphertext)
            
    except FileNotFoundError as e:
        raise
    except IOError as e:
        raise IOError(f"File I/O error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_file_compatible(input_path, output_path, password):
    """Decrypt a [salt][iv][tag][ciphertext] file using AES-256-GCM."""
    try:
        # Check if input file exists
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        with open(input_path, 'rb') as f:
            raw = f.read()
            
        if len(raw) < SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE:
            raise ValueError("File is corrupted or not properly encrypted (too small)")
            
        salt = raw[:SALT_SIZE]
        iv = raw[SALT_SIZE:SALT_SIZE+GCM_IV_SIZE]
        tag = raw[SALT_SIZE+GCM_IV_SIZE:SALT_SIZE+GCM_IV_SIZE+GCM_TAG_SIZE]
        ciphertext = raw[SALT_SIZE+GCM_IV_SIZE+GCM_TAG_SIZE:]

        key = derive_key(password, salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("Decryption failed: The password may be incorrect or the file is corrupted")

        with open(output_path, 'wb') as f:
            f.write(plaintext)
            
    except FileNotFoundError as e:
        raise
    except ValueError as e:
        raise
    except IOError as e:
        raise IOError(f"File I/O error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Unexpected error during decryption: {str(e)}")

# ---- GUI LOGIC ----

def gui_encrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    # Validate input
    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    
    # Validate password strength
    valid, msg = validate_password_strength(password)
    if not valid:
        messagebox.showerror("Error", msg)
        return
    elif msg:  # Warning message
        if not messagebox.askyesno("Weak Password", msg + "\n\nContinue anyway?"):
            return

    try:
        # Generate output path
        out_path = file_path + ".enc"
        
        # Check if output file already exists
        if os.path.exists(out_path):
            if not messagebox.askyesno("Overwrite?", f"File already exists:\n{out_path}\n\nOverwrite?"):
                return
        
        encrypt_file_compatible(file_path, out_path, password)
        messagebox.showinfo("Success", f"✅ File encrypted successfully!\nSaved as:\n{out_path}")
        
    except FileNotFoundError as e:
        messagebox.showerror("Error", f"File not found: {str(e)}")
    except IOError as e:
        messagebox.showerror("Error", f"File I/O error: {str(e)}")
    except ValueError as e:
        messagebox.showerror("Error", f"Encryption error: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")

def gui_decrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    # Validate input
    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid encrypted file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        # Generate output path with better naming logic
        if file_path.endswith(".enc"):
            out_path = file_path[:-4]
        else:
            base_name, ext = os.path.splitext(file_path)
            out_path = f"{base_name}_decrypted{ext}"
        
        # If output file exists, add timestamp
        if os.path.exists(out_path):
            base_name, ext = os.path.splitext(out_path)
            timestamp = int(time.time())
            out_path = f"{base_name}_{timestamp}{ext}"
            messagebox.showinfo("Info", f"Output file exists. Saving with timestamp:\n{out_path}")

        decrypt_file_compatible(file_path, out_path, password)
        messagebox.showinfo("Success", f"✅ File decrypted successfully!\nSaved as:\n{out_path}")
        
    except FileNotFoundError as e:
        messagebox.showerror("Error", f"File not found: {str(e)}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except IOError as e:
        messagebox.showerror("Error", f"File I/O error: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, ctk.END)
        file_entry.insert(0, file_path)

def show_about():
    about_text = """CipherGuard - Secure File Encryption Tool

Version: 2.0
Algorithm: AES-256-GCM
Key Derivation: PBKDF2-SHA256 (100,000 iterations)

Features:
• Authenticated encryption (GCM mode)
• Password-based key derivation
• Cross-platform compatible
• Secure memory handling

Developer: Srishti Bhatt
"""
    messagebox.showinfo("About CipherGuard", about_text)

# ------------------- UI Layout -------------------

title = ctk.CTkLabel(app, text="🔒 Secure File Encryption & Decryption Tool", 
                    font=("Segoe UI", 24, "bold"), text_color="#00b4d8")
title.pack(pady=30)

frame = ctk.CTkFrame(app, corner_radius=15)
frame.pack(pady=20, padx=20, fill="x")

file_label = ctk.CTkLabel(frame, text="Select File:", font=("Segoe UI", 15))
file_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")

file_entry = ctk.CTkEntry(frame, width=400, placeholder_text="Choose file to encrypt/decrypt...")
file_entry.grid(row=0, column=1, padx=10, pady=20)

browse_btn = ctk.CTkButton(frame, text="Browse", width=100, fg_color="#0077b6", 
                          hover_color="#023e8a", command=browse_file)
browse_btn.grid(row=0, column=2, padx=10, pady=20)

password_label = ctk.CTkLabel(frame, text="Enter Password:", font=("Segoe UI", 15))
password_label.grid(row=1, column=0, padx=20, pady=20, sticky="w")

password_entry = ctk.CTkEntry(frame, width=400, show="*", placeholder_text="Enter a strong password (8+ chars)...")
password_entry.grid(row=1, column=1, padx=10, pady=20)

# Button frame for better layout
button_frame = ctk.CTkFrame(app, fg_color="transparent")
button_frame.pack(pady=10)

encrypt_btn = ctk.CTkButton(button_frame, text="🔒 Encrypt File", width=220, height=40,
                            fg_color="#00b4d8", hover_color="#0077b6", command=gui_encrypt_file)
encrypt_btn.pack(side="left", padx=10)

decrypt_btn = ctk.CTkButton(button_frame, text="🔓 Decrypt File", width=220, height=40,
                            fg_color="#ef233c", hover_color="#d90429", command=gui_decrypt_file)
decrypt_btn.pack(side="left", padx=10)

# About button
about_btn = ctk.CTkButton(app, text="ℹ️ About", width=120, height=30,
                        fg_color="#6c757d", hover_color="#495057", command=show_about)
about_btn.pack(pady=10)

footer = ctk.CTkLabel(app, text="Developed by Srishti Bhatt | Cryptography Project | v2.0",
                    font=("Segoe UI", 12), text_color="gray")
footer.pack(side="bottom", pady=15)

# Bind Enter key to trigger encryption (when not in password field)
def on_enter(event):
    if app.focus_get() != password_entry:
        gui_encrypt_file()

app.bind('<Return>', on_enter)

app.mainloop()
