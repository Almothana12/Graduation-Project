import logging
import sys
from threading import Thread

import requests
from PyQt5 import QtCore as qtc
from PyQt5 import QtWidgets as qtw

# import logthread
import command_injection
import data
import main
import sqli
import versions
import xss
from crawler import get_all_links
from ui_form import Ui_MainWindow

session = requests.Session()


class ThreadSignal(qtc.QObject):
    finished = qtc.pyqtSignal()


class QTextEditLogger(logging.Handler, qtc.QObject):
    appendPlainText = qtc.pyqtSignal(str)

    def __init__(self, parent):
        super().__init__()
        qtc.QObject.__init__(self)
        self.widget = qtw.QPlainTextEdit(parent)
        self.widget.setReadOnly(True)
        self.appendPlainText.connect(self.widget.appendPlainText)

    def emit(self, record):
        msg = self.format(record)
        self.appendPlainText.emit(msg)


class MainWindow(qtw.QMainWindow, Ui_MainWindow):

    start_log = qtc.pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        self.scanButton.clicked.connect(self.scan)

        # Enable log messages in terminal
        logging.basicConfig(
            level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', datefmt='%H:%M:%S')

        # Initialize the log box
        self.logTextBox = QTextEditLogger(self)
        # Set the log format of the box
        self.logTextBox.setFormatter(
            logging.Formatter('[%(levelname)s] %(message)s'))
        logging.getLogger().addHandler(self.logTextBox)
        logging.getLogger().setLevel(logging.INFO)

        # Also write logs to WS2T.log with log level=DEBUG
        fh = logging.FileHandler('WS2T.log')
        fh.setLevel(logging.DEBUG)
        # Set the log format of the box
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(module)s %(funcName)s %(message)s'))
        logging.getLogger().addHandler(fh)

        # Add the text box widget to the predefined layout
        self.logLayout.addWidget(self.logTextBox.widget)

        self.urlLineEdit.setText("http://dvwa-win10")
        self.cookieLineEdit.setText(
            "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low")

        self.thread_signal = ThreadSignal()
        self.thread_count = 0
        self.thread_signal.finished.connect(self.thread_finished)

    def scan(self):
        # Clear the log text box
        self.logTextBox.widget.clear()

        # Store what the user chose
        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()
        crawl = self.allPages_radioButton.isChecked()

        if url:
            # if the URL doesn't start with http://, add http:// to the begining to the URL
            if not url.startswith("http://"):
                url = "http://" + url
        else:
            # If no URL entered, show a popup message and return
            qtw.QMessageBox.critical(self, 'Error', 'No URL Entered')
            return
        if cookie:
            session.headers['Cookie'] = cookie
        if not main.valid_url(url, session):
            qtw.QMessageBox.critical(
                self, 'Error', f"Couldn't connect to {url} \nURL not Valid or unreachable")
            return

        self.scanButton.setText("Stop")

        if crawl:
            self.crawl(url)
            return

        threads = []
        if check_version:
            versions_thread = Thread(
                target=versions.check, args=(session, url, self.thread_signal))
            self.thread_count += 1
            versions_thread.start()
            threads.append(versions_thread)
        if check_data:
            data_thread = Thread(
                target=data.check, args=(session, url, self.thread_signal))
            self.thread_count += 1
            data_thread.start()
            threads.append(data_thread)
        if check_sqli:
            sqli_thread = Thread(
                target=sqli.check, args=(session, url, self.thread_signal))
            self.thread_count += 1
            sqli_thread.start()
            threads.append(sqli_thread)
            # if not args['--no-time-based']:
            #     sqli.time_based(session, url)
        if check_xss:
            # dom = not args['--no-dom']
            # cookie = args['--cookie']
            xss_thread = Thread(target=xss.check, args=(
                session, url, True, cookie, self.thread_signal))
            self.thread_count += 1
            xss_thread.start()
            threads.append(xss_thread)
        if check_ci:
            # vulnerable = command_injection.check(session, url)
            ci_thread = Thread(
                target=command_injection.check, args=(session, url, self.thread_signal))
            self.thread_count += 1
            ci_thread.start()
            threads.append(ci_thread)
            # if not vulnerable: TODO
            #     command_injection.time_based(session, url)

    def crawl(self, url):
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()

        urls = get_all_links(session, url)

        if check_version:
            versions_thread = Thread(
                target=versions.check, args=(session, url))
            versions_thread.start()

        threads = []
        for url in urls:
            if check_data:
                data_thread = Thread(
                    target=data.check, args=(session, url, self.thread_signal))
                self.thread_count += 1
                data_thread.start()
                threads.append(data_thread)
            if check_sqli:
                sqli_thread = Thread(
                    target=sqli.check, args=(session, url, self.thread_signal))
                self.thread_count += 1
                sqli_thread.start()
                threads.append(sqli_thread)
                # if not args['--no-time-based']:
                #     sqli.time_based(session, url)
            if check_xss:
                # dom = not args['--no-dom']
                # cookie = args['--cookie']
                xss_thread = Thread(target=xss.check, args=(
                    session, url, True, cookie, self.thread_signal))
                self.thread_count += 1
                xss_thread.start()
                threads.append(xss_thread)
            if check_ci:
                # vulnerable = command_injection.check(session, url)
                ci_thread = Thread(
                    target=command_injection.check, args=(session, url, self.thread_signal))
                self.thread_count += 1
                ci_thread.start()
                threads.append(ci_thread)
                # if not vulnerable: TODO
                #     command_injection.time_based(session, url)

    def thread_finished(self):
        self.thread_count -= 1
        if self.thread_count == 0:
            session.close()
            self.scanButton.setText("Scan")
            qtw.QMessageBox.information(self, 'Scan Complete', 'Scan Complete')


def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
