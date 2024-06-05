import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("gate.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key(key_path):
    with open(key_path, "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path):
    key = generate_key()
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    enc_file_path = file_path + ".enc"
    with open(enc_file_path, "wb") as enc_file:
        enc_file.write(encrypted)
    messagebox.showinfo("Success", f"File encrypted successfully!\nEncrypted file: {enc_file_path}\nKey file: gate.key")

def decrypt_file(enc_file_path, key_path):
    try:
        key = load_key(key_path)
        fernet = Fernet(key)
        with open(enc_file_path, "rb") as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        original_file_path = enc_file_path[:-4]
        with open(original_file_path, "wb") as dec_file:
            dec_file.write(decrypted)
        messagebox.showinfo("Success", f"File decrypted successfully!\nDecrypted file: {original_file_path}")
    except Exception as e:
        messagebox.showerror("Error", "Incorrect key file")

def encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt_file(file_path)

def decrypt():
    enc_file_path = filedialog.askopenfilename(title="Select the .enc file", filetypes=[("Encrypted files", "*.enc")])
    if enc_file_path:
        key_path = filedialog.askopenfilename(title="Select the gate.key file", filetypes=[("Key files", "*.key")])
        if key_path:
            decrypt_file(enc_file_path, key_path)

# GUI setup
root = tk.Tk()
root.title("Paline File Encryptor/Decryptor")
root.geometry("400x200")
root.configure(bg="#f0f0f0")

# Title and Instructions
title_label = tk.Label(root, text="Paline File Encryptor/Decryptor", font=("Helvetica", 16), bg="#f0f0f0")
title_label.pack(pady=10)

instructions_label = tk.Label(root, text="Encrypt or decrypt files using a generated key.", font=("Helvetica", 10), bg="#f0f0f0")
instructions_label.pack(pady=5)

frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=20)

# Style Buttons
style = ttk.Style()
style.configure("TButton", font=("Helvetica", 10), padding=10)

encrypt_button = ttk.Button(frame, text="Encrypt File", command=encrypt)
encrypt_button.grid(row=0, column=0, padx=20, pady=10)

decrypt_button = ttk.Button(frame, text="Decrypt File", command=decrypt)
decrypt_button.grid(row=0, column=1, padx=20, pady=10)

# Status Bar
status_label = tk.Label(root, text="", font=("Helvetica", 10), bg="#f0f0f0", anchor='w')
status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

root.mainloop()
