from PyQt5.QtWidgets import QSplashScreen, QLabel, QVBoxLayout
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt

def show_splash_screen():
    pixmap = QPixmap("splash_image.png")
    splash = QSplashScreen(pixmap)
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    label = QLabel("Loading...")
    layout = QVBoxLayout()
    layout.addWidget(label)
    splash.setLayout(layout)
    splash.show()
    return splash
