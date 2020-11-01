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
session.headers['Cookie'] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"


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

        self.logTextBox = QTextEditLogger(self)
        # You can format what is printed to text box
        self.logTextBox.setFormatter(
            logging.Formatter('[%(levelname)s] %(message)s'))
        logging.getLogger().addHandler(self.logTextBox)
        # You can control the logging level
        logging.getLogger().setLevel(logging.INFO)

        fh = logging.FileHandler('WS2T.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s'))
        logging.getLogger().addHandler(fh)

        self.logLayout.addWidget(self.logTextBox.widget)

    def scan(self):
        self.logTextBox.widget.clear()

        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()
        crawl = self.allPages_radioButton.isChecked()

        if url:
            # if the URL doesn't start with http://, add it to the begining to the URL
            if not url.startswith("http://"):
                url = "http://" + url
        else:
            # If no URL entered, show a popup message and return
            qtw.QMessageBox.critical(self, 'Error', 'No URL Entered')
            return
        if cookie:
            session.headers['Cookie'] = cookie
        if not main.valid_url(url, session):
            qtw.QMessageBox.critical(self, 'Error', 'No Valid URL')
            return

        self.scanButton.setText("Stop")

        if crawl:
            self.crawl(url)
            return

        threads = []
        if check_version:
            versions_thread = Thread(
                target=versions.check, args=(session, url))
            versions_thread.start()
            threads.append(versions_thread)
        if check_data:
            data_thread = Thread(target=data.check, args=(session, url))
            data_thread.start()
            threads.append(data_thread)
        if check_sqli:
            sqli_thread = Thread(target=sqli.check, args=(session, url))
            sqli_thread.start()
            threads.append(sqli_thread)
            # if not args['--no-time-based']:
            #     sqli.time_based(session, url)
        if check_xss:
            # dom = not args['--no-dom']
            # cookie = args['--cookie']
            xss_thread = Thread(target=xss.check, args=(
                session, url, True, cookie))
            xss_thread.start()
            threads.append(xss_thread)
        if check_ci:
            # vulnerable = command_injection.check(session, url)
            ci_thread = Thread(
                target=command_injection.check, args=(session, url))
            ci_thread.start()
            threads.append(ci_thread)
            # if not vulnerable: TODO
            #     command_injection.time_based(session, url)
        # self.wait_for_threads(threads)
        # session.close()
        self.scanButton.setText("Scan")
        # self.show_popup()

    def show_popup(self):
        msg = qtw.QMessageBox()
        msg.setWindowTitle("Scan Complete")
        msg.setText("Scan Complete")
        msg.setIcon(qtw.QMessageBox.Information)
        msg.setStandardButtons(qtw.QMessageBox.Ok)
        msg.exec_()

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
                data_thread = Thread(target=data.check, args=(session, url))
                data_thread.start()
                threads.append(data_thread)
            if check_sqli:
                sqli_thread = Thread(target=sqli.check, args=(session, url))
                sqli_thread.start()
                threads.append(sqli_thread)
                # if not args['--no-time-based']:
                #     sqli.time_based(session, url)
            if check_xss:
                # dom = not args['--no-dom']
                # cookie = args['--cookie']
                xss_thread = Thread(target=xss.check, args=(
                    session, url, True, cookie))
                xss_thread.start()
                threads.append(xss_thread)
            if check_ci:
                # vulnerable = command_injection.check(session, url)
                ci_thread = Thread(
                    target=command_injection.check, args=(session, url))
                ci_thread.start()
                threads.append(ci_thread)
                # if not vulnerable: TODO
                #     command_injection.time_based(session, url)

        # self.wait_for_threads(threads)
        # session.close()
        self.scanButton.setText("Scan")
        # self.show_popup()

    def wait_for_threads(self, threads):
        while True:
            all_done = True
            for thread in threads:
                if thread.is_alive():
                    all_done = False
                else:
                    threads.remove(thread)
            if all_done:
                return


def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
