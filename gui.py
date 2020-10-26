import sys

import requests
from PyQt5 import QtCore as qtc
from PyQt5 import QtWidgets as qtw
from threading import Thread
import time

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

log_started = False


class MainWindow(qtw.QMainWindow, Ui_MainWindow):

    start_log = qtc.pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        self.scanButton.clicked.connect(self.scan)
        # Create a worker object and a thread
        self.worker = Worker()
        self.worker_thread = qtc.QThread()
        self.worker.log_signal.connect(self.show_log)
        self.start_log.connect(self.worker.run)

        # Assign the worker to the thread and start the thread
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.start()

        self.start_log.emit()

    def scan(self):
        open('logs/info.log', 'w').close()

        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()

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
            # TODO make GUI warnings
            return

        self.scanButton.setText("Stop")

        # if args['--crawl']: TODO
        #     crawl(url, args)
        #     return
        threads = []
        if check_version:
            # versions.check(session, url)
            versions_thread = Thread(
                target=versions.check, args=(session, url))
            versions_thread.start()
            threads.append(versions_thread)
        if check_data:
            # data.check(session, url)
            data_thread = Thread(target=data.check, args=(session, url))
            data_thread.start()
            threads.append(data_thread)
        if check_sqli:
            # sqli.check(session, url)
            sqli_thread = Thread(target=sqli.check, args=(session, url))
            sqli_thread.start()
            threads.append(sqli_thread)

            
            # if not args['--no-time-based']:
            #     sqli.time_based(session, url)
        if check_xss:
            # dom = not args['--no-dom']
            # cookie = args['--cookie']

            xss_thread = Thread(target=xss.check, args=(session, url, True, cookie))
            xss_thread.start()
            threads.append(xss_thread)

            print(type(xss_thread.is_alive()))
            # xss.check(session, url, True, cookie)
        if check_ci:
            # vulnerable = command_injection.check(session, url)
            ci_thread = Thread(target=command_injection.check, args=(session, url))
            ci_thread.start()
            threads.append(ci_thread)

            # if not vulnerable:
            #     command_injection.time_based(session, url)

        # time.sleep(2)
        # self.scanButton.setText("Scan")
        while True:
            for t in threads:
                if t.is_alive():
                    continue
            self.scanButton.setText("Scan")
            self.show_popup()
            break
        # output.close()

    def show_popup(self):
        msg = qtw.QMessageBox()
        msg.setWindowTitle("Scan Complete")
        msg.setText("Scan Complete")
        msg.setIcon(qtw.QMessageBox.Information)
        msg.setStandardButtons(qtw.QMessageBox.Ok)
        msg.exec_()

    def show_log(self):
        self.textBrowser.setPlainText(open('logs/info.log').read())


class Worker(qtc.QObject):

    log_signal = qtc.pyqtSignal()

    @qtc.pyqtSlot()
    def run(self):
        while True:
            self.log_signal.emit()
            time.sleep(1)


def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    import logformatter
    logformatter.start_logging(console_file="logs/info.log")
    run()
