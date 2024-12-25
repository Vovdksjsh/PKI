import tkinter as tk
import tkinter.messagebox as msg
from tkinter import filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print(public_key, private_key)
    return private_key, public_key

def load_file():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as file:
        return file.read()

def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

def encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.btn0 = tk.Button(self, text='Generate keys', command=self.generate)
        self.btn0.pack(padx=50, pady=2)
        self.btn1 = tk.Button(self, text='Encrypt file', command=self.encrypt_file)
        self.btn1.pack(padx=50, pady=2)
        self.btn2 = tk.Button(self, text='Decrypt file', command=self.decrypt_file)
        self.btn2.pack(padx=50, pady=2)
        self.btn3 = tk.Button(self, text='Sign file', command=self.sign_file)
        self.btn3.pack(padx=50, pady=2)
        self.btn4 = tk.Button(self, text='Verify signature', command=self.verify_signature)
        self.btn4.pack(padx=50, pady=2)

    def generate(self):
        self.private_key, self.public_key = generate_keys()
        msg.showinfo('Notification', 'Key pair generated!')

    def encrypt_file(self):
        file_data = load_file()
        if file_data:
            self.encrypted_data = encrypt(self.public_key, file_data)
            save_to_file(self.encrypted_data, 'encrypted_file.docx')
            msg.showinfo('Notification', 'File encrypted and saved as encrypted_file.docx!')

    def decrypt_file(self):
        if hasattr(self, 'encrypted_data'):
            decrypted_data = decrypt(self.private_key, self.encrypted_data)
            save_to_file(decrypted_data, 'decrypted_file.docx')
            msg.showinfo('Notification', 'File decrypted and saved as decrypted_file.docx!')
        else:
            msg.showinfo('Error', 'No encrypted data found. Please encrypt a file first.')

    def sign_file(self):
        file_data = load_file()
        if file_data:
            self.signature = sign(self.private_key, file_data)
            save_to_file(self.signature, 'signature.sig')
            msg.showinfo('Notification', 'File signed and signature saved as signature.sig!')

    def verify_signature(self):
        if hasattr(self, 'signature'):
            file_data = load_file()
            if file_data:
                is_valid = verify(self.public_key, file_data, self.signature)
                if is_valid:
                    msg.showinfo('Notification', 'Signature is valid!')
                else:
                    msg.showinfo('Notification', 'Signature is not valid!')
        else:
            msg.showinfo('Error', 'No signature found. Please sign a file first.')

if __name__ == '__main__':
    app = App()
    app.title('Encryption App')
    app.mainloop()
