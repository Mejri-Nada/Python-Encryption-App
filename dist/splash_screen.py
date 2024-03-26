from PyQt5.QtWidgets import QApplication, QSplashScreen
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QTimer

def show_splash_screen(duration=5000, image_path='logo4.jpg'):
    app = QApplication([])

    splash_pix = QPixmap(image_path)
    splash = QSplashScreen(splash_pix)
    splash.show()

    timer = QTimer()
    timer.setInterval(duration)
    timer.setSingleShot(True)
    timer.timeout.connect(splash.close)
    timer.start()

    app.exec_()
