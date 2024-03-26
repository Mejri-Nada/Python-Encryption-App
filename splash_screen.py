from PyQt5.QtWidgets import QSplashScreen, QLabel, QVBoxLayout
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt,QTimer

def show_splash_screen():
    pixmap = QPixmap("logo4.jpg")
    splash = QSplashScreen(pixmap)
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    label = QLabel("Loading...")
    layout = QVBoxLayout()
    layout.addWidget(label)
    splash.setLayout(layout)
    splash.show()
    QTimer.singleShot(2000, splash.close)
    return splash
