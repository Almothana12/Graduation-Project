import logging
import sys
from threading import Thread

import requests
from PyQt5 import QtCore as qtc
from PyQt5 import QtWidgets as qtw

import command_injection
import data
import sqli
import versions
import xss
from report.report_generator import generate_report
from ui.ui_form import Ui_MainWindow
from utils.url_vaildator import valid_url
from utils.crawler import get_all_links

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount("http://", adapter)


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

        self.urlLineEdit.setText("http://dvwa-ubuntu")
        self.cookieLineEdit.setText(
            "PHPSESSID=ctgd2jigvorbntt2hfm4o7sltm; security=low")

        self.thread_signal = ThreadSignal()
        self.alive_thread_count = 0
        self.max_thread_count = 0
        self.stop_threads = False
        self.threads = []
        self.thread_signal.finished.connect(self.thread_finished)
        self.progressBar.setHidden(True)

    def scan(self):
        if self.scanButton.text() == "Stop" or self.scanButton.text() == "Stopping...":
            # Abort scanning. Stop the threads
            self.scanButton.setText("Stopping...")
            self.stop_threads = True
            self.progressBar.setMaximum(0)
            return

        # Clear the log text box
        self.logTextBox.widget.clear()

        # The total number of threads
        self.max_thread_count = 0
        # The number of alive threds
        self.alive_thread_count = 0

        self.stop_threads = False

        # get what the user chose
        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()
        check_time_based = False  # TODO
        check_dom_based = False  # TODO
        crawl = self.allPages_radioButton.isChecked()

        if url:
            # if the URL doesn't start with http:// or https://, add http:// to the begining to the URL
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
        else:
            # If no URL entered, show a popup message and return
            qtw.QMessageBox.critical(self, 'Error', 'No URL Entered')
            return
        if cookie:
            session.headers['Cookie'] = cookie
        if not valid_url(url, session):
            qtw.QMessageBox.critical(
                self, 'Error', f"Could not connect to {url} \nURL not valid or unreachable")
            return

        self.scanButton.setText("Stop")
        # Show the progress bar
        self.progressBar.setHidden(False)

        # List containing all urls to scan
        urls = []
        if crawl:
            urls = get_all_links(session, url)
            if len(urls) > 1:
                logging.info(f"Scanning {len(urls)} pages")
        else:
            # Scan only one URL
            urls.append(url)

        if check_version:
            versions_thread = Thread(
                target=versions.check, args=(session, url, self.thread_signal, lambda: self.stop_threads))
            self.max_thread_count += 1
            self.alive_thread_count += 1
            versions_thread.start()

        for url in urls:
            if check_data:
                data_thread = Thread(
                    target=data.check, args=(session, url, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                data_thread.start()
            if check_sqli:
                sqli_thread = Thread(target=sqli.check, args=(
                    session, url, check_time_based, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                sqli_thread.start()

            if check_xss:
                xss_thread = Thread(target=xss.check, args=(
                    session, url, check_dom_based, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                xss_thread.start()
            if check_ci:
                ci_thread = Thread(target=command_injection.check, args=(
                    session, url, check_time_based, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                ci_thread.start()


    def thread_finished(self):
        # A thread is finished
        self.alive_thread_count -= 1
        if self.alive_thread_count == 0:
            # No threads left
            # Set the progress bar to 100%
            self.progressBar.setValue(100)
            # close the requests session
            session.close()
            if self.scanButton.text() != "Stopping...":
                # The threads finished normally
                self.scan_complete()
            else:
                # The threads was stopped by the user
                # Return the progress bar to normal. 
                self.progressBar.setMaximum(100)
                # Show a popup
                qtw.QMessageBox.information(
                    self, 'Scan Stopped', 'Scanning Stopped successfully')
            self.scanButton.setText("Scan")
        else:
            # Update the progress bar
            finished_threads = self.max_thread_count - self.alive_thread_count
            percentage = finished_threads / self.max_thread_count * 100
            self.progressBar.setValue(int(percentage))

    def scan_complete(self):
        msg = qtw.QMessageBox()
        msg.setWindowTitle("Scan Complete")
        msg.setText("Scan completed successfully.")
        msg.setInformativeText("Do you want to generate an HTML report?")
        msg.setIcon(qtw.QMessageBox.Information)
        msg.addButton(qtw.QPushButton("Generate Report"), qtw.QMessageBox.ActionRole)
        msg.setStandardButtons(qtw.QMessageBox.Ok)
        msg.setDefaultButton(qtw.QMessageBox.Ok)
        msg.setDetailedText("DETAILS")

        msg.buttonClicked.connect(self.popup_button)
        msg.exec_()

    def popup_button(self, button):
        button_clicked = button.text()
        if button_clicked == "OK":
            return
        elif button_clicked == "Generate Report":
            generate_report()

def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
