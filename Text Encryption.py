import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CFB, get_random_bytes(AES.block_size))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def decrypt_aes(ciphertext, key):
    decoded_ciphertext = base64.b64decode(ciphertext)
    iv = decoded_ciphertext[:AES.block_size]
    ciphertext = decoded_ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_CFB, get_random_bytes(DES.block_size))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def decrypt_des(ciphertext, key):
    decoded_ciphertext = base64.b64decode(ciphertext)
    iv = decoded_ciphertext[:DES.block_size]
    ciphertext = decoded_ciphertext[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CFB, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode('utf-8')

def encrypt_rsa(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa(ciphertext, private_key):
    decoded_ciphertext = base64.b64decode(ciphertext)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(decoded_ciphertext).decode('utf-8')

def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    algorithm = algorithm_var.get()

    if not plaintext:
        messagebox.showerror("Error", "Please enter plaintext.")
        return

    try:
        if algorithm == "AES":
            key = b'Sixteen byte key'  # 128-bit key
            ciphertext = encrypt_aes(plaintext, key)
        elif algorithm == "DES":
            key = b'EightByt'  # 64-bit key
            ciphertext = encrypt_des(plaintext, key)
        elif algorithm == "RSA":
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            ciphertext = encrypt_rsa(plaintext, public_key)
            # Store keys for decryption. In real use, handle keys securely!
            root.private_key = private_key
            root.public_key = public_key

        ciphertext_window = tk.Toplevel(root)
        ciphertext_window.title("Encrypted Text")
        ciphertext_text = scrolledtext.ScrolledText(ciphertext_window, wrap=tk.WORD)
        ciphertext_text.insert(tk.END, ciphertext)
        ciphertext_text.pack(expand=True, fill=tk.BOTH)
        root.ciphertext = ciphertext #store for decryption

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_text():
    algorithm = algorithm_var.get()
    try:
        ciphertext = root.ciphertext
    except:
        messagebox.showerror("Error", "Please Encrypt text first.")
        return

    try:
        if algorithm == "AES":
            key = b'Sixteen byte key'
            plaintext = decrypt_aes(ciphertext, key)
        elif algorithm == "DES":
            key = b'EightByt'
            plaintext = decrypt_des(ciphertext, key)
        elif algorithm == "RSA":
            if not hasattr(root, 'private_key'):
                messagebox.showerror("Error", "RSA private key not available. Encrypt first.")
                return
            plaintext = decrypt_rsa(ciphertext, root.private_key)

        plaintext_window = tk.Toplevel(root)
        plaintext_window.title("Decrypted Text")
        plaintext_text = scrolledtext.ScrolledText(plaintext_window, wrap=tk.WORD)
        plaintext_text.insert(tk.END, plaintext)
        plaintext_text.pack(expand=True, fill=tk.BOTH)

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

root = tk.Tk()
root.title("Text Encryption/Decryption")

algorithm_var = tk.StringVar(root)
algorithm_var.set("AES")  # Default algorithm

algorithm_label = tk.Label(root, text="Select Algorithm:")
algorithm_label.pack()

algorithm_menu = tk.OptionMenu(root, algorithm_var, "AES", "DES", "RSA")
algorithm_menu.pack()

plaintext_label = tk.Label(root, text="Plaintext:")
plaintext_label.pack()

plaintext_entry = scrolledtext.ScrolledText(root, wrap=tk.WORD)
plaintext_entry.pack(expand=True, fill=tk.BOTH)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

root.mainloop()