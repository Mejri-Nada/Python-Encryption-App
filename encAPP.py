from PyQt5 import QtCore;
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QComboBox, QInputDialog, QLineEdit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QComboBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QFileDialog,
    QComboBox,
    QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QGraphicsBlurEffect, QLabel
from PyQt5.QtGui import QPixmap
from PyQt5.QtGui import QFont



class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.init_ui()

    def init_ui(self):

        self.setWindowTitle('My Encryption App')

        self.setFixedSize(800, 500)

        self.text_edit = QTextEdit(self)

        
        # Add an image label
        # Load the image and scale it to the desired size
        image = QPixmap('logo4.jpg')
        image = image.scaledToWidth(image.width()//4)  # Resize by 50%
        

        # Create a QLabel and set the image
        image_label = QLabel(self)
        image_label.setPixmap(image)
        image_label.setAlignment(Qt.AlignCenter)
        image_label.setObjectName('img')

        #close button
        exit_button = QPushButton('close', self)
        exit_button.setObjectName('exitButton')

        # Add plain text label
        text_label = QLabel('Mejri Encrypto App', self)
        text_label.setObjectName('name')
        text_label.setAlignment(Qt.AlignCenter)

        # Set font attributes for the text label
        font = QFont()
        font.setFamily("Sans Serif")
        font.setBold(True)
        font.setPointSize(10)  # Adjust the size as needed
        text_label.setFont(font)



        encrypt_button = QPushButton('Encrypt', self)
        decrypt_button = QPushButton('Decrypt', self)
        file_button = QPushButton('Select File', self)
        self.algorithm_combo = QComboBox(self)
        self.algorithm_combo.addItems(['AES', 'DES', 'RSA'])
        self.algorithm_combo.currentIndexChanged.connect(self.update_algorithm)

        exit_button.clicked.connect(lambda: app.exit())
        encrypt_button.clicked.connect(self.encrypt_text)
        decrypt_button.clicked.connect(self.decrypt_text)
        file_button.clicked.connect(self.select_file)

        # Style

        vbox_buttons = QVBoxLayout()
        vbox_buttons.addWidget(self.algorithm_combo)
        vbox_buttons.addWidget(encrypt_button)
        vbox_buttons.addWidget(decrypt_button)
        vbox_buttons.addWidget(file_button)
        

        hbox_main = QHBoxLayout()
        hbox_main.addWidget(self.text_edit)
        hbox_main.addLayout(vbox_buttons)
        
        vbox_main = QVBoxLayout()
        vbox_main.addWidget(exit_button)
        vbox_main.addWidget(image_label)
        vbox_main.addWidget(text_label)
        vbox_main.addLayout(hbox_main)

        self.setLayout(vbox_main)


        # Initialize the algorithm and generate RSA keys
        self.update_algorithm()
        self.generate_rsa_keys()

    def update_algorithm(self):
        self.selected_algorithm = self.algorithm_combo.currentText()

    def generate_rsa_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt_text(self):
        plaintext = self.text_edit.toPlainText() #the text entered

        if self.selected_algorithm == 'AES': #combobox choice1
            password, ok = QInputDialog.getText(self, 'Password Input', 'Enter your password:', QLineEdit.Password) #typeKey
            if not ok:
                return  # User canceled the input
            key = self.derive_key(password) #key=passwprd
            cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        elif self.selected_algorithm == 'DES':  #combobox choice2
            password, ok = QInputDialog.getText(self, 'Password Input', 'Enter your password:', QLineEdit.Password)
            if not ok:
                return  # User canceled the input
            key = self.derive_key(password)
            cipher = Cipher(algorithms.TripleDES(key[:24]), modes.CFB(key[:8]), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        elif self.selected_algorithm == 'RSA':  #combobox choice3
            ciphertext = self.public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.text_edit.clear()
            self.text_edit.setPlainText(urlsafe_b64encode(ciphertext).decode())
            return
        else:
            # Handle unsupported algorithm
            return

        self.text_edit.clear()
        self.text_edit.setPlainText(urlsafe_b64encode(ciphertext).decode())

    def decrypt_text(self):
        encrypted_text = self.text_edit.toPlainText()

        if self.selected_algorithm in ['AES', 'DES']:
            password, ok = QInputDialog.getText(self, 'Password Input', 'Enter your password:', QLineEdit.Password)
            if not ok:
                return  # User canceled the input
            key = self.derive_key(password)

        if self.selected_algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(urlsafe_b64decode(encrypted_text.encode())) + decryptor.finalize()
        elif self.selected_algorithm == 'DES':
            cipher = Cipher(algorithms.TripleDES(key[:24]), modes.CFB(key[:8]), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(urlsafe_b64decode(encrypted_text.encode())) + decryptor.finalize()
        elif self.selected_algorithm == 'RSA':
            ciphertext = urlsafe_b64decode(encrypted_text.encode())
            try:
                decrypted_text = self.private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                print(f"Decryption failed: {e}")
                return
        else:
            # Handle unsupported algorithm
            return

        self.text_edit.clear()
        self.text_edit.setPlainText(decrypted_text.decode())

    def derive_key(self, password):
        salt = b'salt_example'  # Change this for better security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Adjust for desired security level
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def select_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Text File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.text_edit.setPlainText(content)

if __name__ == '__main__':
    app = QApplication([])
    window = EncryptionApp()
    with open('styles.qss', 'r') as file:
        style = file.read()
        app.setStyleSheet(style)
    
    window.show()
    app.exec_()