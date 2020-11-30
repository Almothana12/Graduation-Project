import logging
import os
import subprocess
import sys
from datetime import datetime
from platform import system
from threading import Thread
from time import sleep

import requests
from PyQt5 import QtCore as qtc
from PyQt5 import QtGui as qtg
from PyQt5 import QtWidgets as qtw

import command_injection
import data
import sqli
import versions
import xss
from report import report_generator
from ui import resources
from ui.ui_form import Ui_MainWindow
from utils.crawler import get_all_links
from utils.url_vaildator import valid_url

log = logging.getLogger(__name__)

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount("http://", adapter)


class ThreadSignal(qtc.QObject):
    finished = qtc.pyqtSignal()


class QTextEditLogger(logging.Handler, qtc.QObject):
    appendText = qtc.pyqtSignal(str)

    def __init__(self, parent):
        super().__init__()
        qtc.QObject.__init__(self)
        self.widget = qtw.QTextEdit(parent)
        self.widget.setReadOnly(True)
        self.appendText.connect(self.widget.append)
        self.setLevel("INFO")

    def emit(self, record):
        msg = self.format(record)
        # Esacpe HTML
        msg = msg.replace("<", "&lt;")
        msg = msg.replace(">", "&gt;")
        # Color the message depending on log level
        if "[WARNING]" in msg:
            msg = '<span style="color: #e68a00">' + msg + "</span>"
        if "[ERROR]" in msg or "[CRITICAL]" in msg:
            msg = '<span style="color: #cc0000">' + msg + "</span>"
        # Write the message to the text box
        self.appendText.emit(msg)


class MainWindow(qtw.QMainWindow, Ui_MainWindow):
    UrlError = qtc.pyqtSignal(str)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)

        # Connect signals
        # Connect the scan button
        self.scanButton.clicked.connect(self.prepare_scan)
        # Show the about and about Qt page when clicking on the about button
        self.actionAbout.triggered.connect(lambda: qtw.QMessageBox.about(self, "About", "Web Security Testing Tool"))
        self.actionAbout_Qt.triggered.connect(lambda: qtw.QMessageBox.aboutQt(self, "About Qt"))
        # Connect the URLError signal to show an error popup
        self.UrlError.connect(self.errorPopup)
        # Connect checkboxes and radio buttons to show/hide scan options
        self.customScanRadioButton.clicked.connect(self.toggle_checkboxes)
        self.qucikScanRadioButton.clicked.connect(self.toggle_checkboxes)
        self.fullScanRadioButton.clicked.connect(self.toggle_checkboxes)
        self.sqliCheckBox.clicked.connect(self.toggle_checkboxes)
        self.xssCheckBox.clicked.connect(self.toggle_checkboxes)
        self.ciCheckBox.clicked.connect(self.toggle_checkboxes)

        # Set the window icon
        icon = qtg.QIcon()
        icon.addPixmap(qtg.QPixmap(":/logo.png"), qtg.QIcon.Normal, qtg.QIcon.Off)
        self.setWindowIcon(icon)

        # Initialize the log box
        self.logTextBox = QTextEditLogger(self)
        self.logTextBox.widget.setVisible(False)
        # Set the log format of the box
        self.logTextBox.setFormatter(
            logging.Formatter('[%(levelname)s] %(message)s'))
        logging.getLogger().addHandler(self.logTextBox)
        # Add the text box widget to the predefined layout
        self.logLayout.addWidget(self.logTextBox.widget)
        # self.urlLineEdit.setText("http://dvwa-ubuntu/vulnerabilities/sqli/")
        self.urlLineEdit.setText("http://dvwa-win10/vulnerabilities/xss_r/")
        # self.urlLineEdit.setText("http://www.insecurelabs.org/Task/Rule1")
        self.cookieLineEdit.setText(
            "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low")

        # Initialize variables
        self.alive_thread_count = 0
        self.max_thread_count = 0
        self.stop_threads = False
        self.threads = []
        # Signal for each thread. Will emit after thread finished
        self.thread_signal = ThreadSignal()
        self.thread_signal.finished.connect(self.thread_finished)
        # Hide the progress bar and the scan options
        self.progressBar.setHidden(True)
        self.toggle_checkboxes()


    def errorPopup(self, text):
        qtw.QMessageBox.critical(self, 'Error', text)


    def prepare_scan(self):
        """This function is called before scanning. 
        Prepare for scanning and then start the scan thread
        """
        if self.scanButton.text() == "Stop" or self.scanButton.text() == "Stopping...":
            # Abort scanning. Stop the threads
            self.scanButton.setText("Stopping...")
            self.stop_threads = True
            # Stop the progress bar
            self.progressBar.setMaximum(0)
            return

        # Initializing variables for report generation
        report_generator.pages = []
        report_generator.versions = []
        report_generator.vuln_count = 0
        # Get the datetime without microseconds
        report_generator.start_time = datetime.now().replace(microsecond=0)

        # Clear the log text box
        self.logTextBox.widget.clear()
        # Change the text of the button to "Stop"
        self.scanButton.setText("Stop")
        # The total number of threads
        self.max_thread_count = 0
        # The number of alive threds
        self.alive_thread_count = 0
        # Stop flag
        self.stop_threads = False

        # Show the log box and the progress bar
        self.logTextBox.widget.setVisible(True)
        self.progressBar.setHidden(False)
        self.progressBar.setValue(0)
        # Make the progress bar in loading state
        self.progressBar.setMaximum(0)

        # Start the scan thread
        scan = Thread(target=self._scan)
        scan.start()

    def _scan(self):
        # Get what the entered URL and the cookie
        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()

        # Check if quick scan or full scan is selected
        fullscan = self.fullScanRadioButton.isChecked()
        quickscan = self.qucikScanRadioButton.isChecked()

        # Check for these if quick scan, full scan, or the checkbox is checked
        check_xss = quickscan or fullscan or self.xssCheckBox.isChecked()
        check_sqli = quickscan or fullscan or self.sqliCheckBox.isChecked()
        check_ci = quickscan or fullscan or self.ciCheckBox.isChecked()
        check_version = quickscan or fullscan or self.versionCheckBox.isChecked()
        check_data = quickscan or fullscan or self.dataCheckBox.isChecked()

        # Check whether to check for all pages
        crawl = self.allPagesRadioButton.isChecked()

        # Check DOM and time-based if full scan or selected
        check_sql_time = fullscan or self.sqlTimeCheckBox.isChecked()
        check_ci_time = fullscan or self.ciTimeCheckBox.isChecked()
        check_dom_based = fullscan or self.domCheckBox.isChecked()

        # Check if there is a URL and is valid
        if url:
            # if the URL doesn't start with http:// or https://, add http:// to the begining to the URL
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            # Add the URL to the report
            report_generator.url = url
            # Add the cookie to the session if it exists
            if cookie:
                session.headers['Cookie'] = cookie
            # Check that the URL is valid and reachable
            if not valid_url(url, session):
                self.UrlError.emit(
                    f"Could not connect to {url} \nURL not valid or unreachable")
                self.scanButton.setText("Scan")
                self.progressBar.setVisible(False)
                return
        else:
            # No URL entered
            self.UrlError.emit("No URL Entered")
            self.scanButton.setText("Scan")
            self.progressBar.setVisible(False)
            return

        # List containing all urls to scan
        urls = []
        if crawl:
            urls = get_all_links(session, url)
            report_generator.pages_count = len(urls)
            if len(urls) > 1:
                log.info(f"Scanning {len(urls)} pages")
        else:
            # Scan only one URL
            urls.append(url)
            report_generator.pages_count = 1

        if check_version:
            versions_thread = Thread(
                target=versions.check, args=(session, url, self.thread_signal, lambda: self.stop_threads, False))
            self.max_thread_count += 1
            self.alive_thread_count += 1
            versions_thread.start()
        # Start the progress bar
        self.progressBar.setMaximum(100)
        # For each page start threads to check for selcted vulnerabilities
        for url in urls:
            if self.stop_threads:
                return
            if check_data:
                data_thread = Thread(
                    target=data.check, args=(session, url, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                data_thread.start()
            if check_sqli:
                sqli_thread = Thread(target=sqli.check, args=(
                    session, url, check_sql_time, fullscan, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                sqli_thread.start()
            if check_xss:
                xss_thread = Thread(target=xss.check, args=(
                    session, url, check_dom_based, fullscan, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                xss_thread.start()
            if check_ci:
                ci_thread = Thread(target=command_injection.check, args=(
                    session, url, check_ci_time, self.thread_signal, lambda: self.stop_threads))
                self.max_thread_count += 1
                self.alive_thread_count += 1
                ci_thread.start()

    def thread_finished(self):
        """This will be called each time a thread is finished.
        Updates the progress bar and if all threads finished it will show a popup
        """
        # A thread is finished
        self.alive_thread_count -= 1
        if self.alive_thread_count == 0:
            # No threads left
            # Set the progress bar to 100%
            self.progressBar.setValue(100)
            # close the requests session
            session.close()
            # Close the browser
            xss.quit()
            # Record the finish time
            report_generator.finish_time = datetime.now().replace(microsecond=0)
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
            # There are threads that are still running
            # Update the progress bar
            finished_threads = self.max_thread_count - self.alive_thread_count
            percentage = finished_threads / self.max_thread_count * 100
            self.progressBar.setValue(int(percentage))

    def scan_complete(self):
        """Create a popup window and prompt the user for report generation.
        """
        log.debug("Scan Complete")
        msgbox = qtw.QMessageBox()
        msgbox.setWindowTitle("Scan Complete")
        if report_generator.vuln_count:
            # Vulnerabilities found.
            msgbox.setText(f"Scan completed successfully. \n{report_generator.vuln_count} vulnerabilities found.")
            msgbox.setIcon(qtw.QMessageBox.Warning)
        else:
            # No vulnerabilities found.
            msgbox.setText("Scan completed successfully. No vulnerabilities found.")
            msgbox.setIcon(qtw.QMessageBox.Information)
        msgbox.setInformativeText("Do you want to generate a report file?")
        msgbox.addButton("Generate Report", qtw.QMessageBox.ActionRole)
        msgbox.setStandardButtons(qtw.QMessageBox.Ok)
        msgbox.setDefaultButton(qtw.QMessageBox.Ok)
        # msgbox.setDetailedText("DETAILS")

        reply = msgbox.exec_()
        if reply == qtw.QMessageBox.Ok:
            return
        else:
            # Generate report
            msgbox = qtw.QMessageBox()
            msgbox.setWindowTitle("Scan Complete")
            msgbox.setText('Do you want to generate an HTML report or a PDF report?')
            msgbox.setIcon(qtw.QMessageBox.Question)
            html_button = msgbox.addButton("HTML", qtw.QMessageBox.ActionRole)
            pdf_button = msgbox.addButton("PDF", qtw.QMessageBox.ActionRole)
            msgbox.exec_()
            if msgbox.clickedButton() == html_button:
                log.debug("Generating HTML report")
                report_path = report_generator.generate_report(pdf=False)
            elif msgbox.clickedButton() == pdf_button:
                log.debug("Generating PDF report")
                report_path = report_generator.generate_report(pdf=True)
            else:
                # Should never be reached
                return
            if report_path:
                # Report has generated
                log.debug("Report generated")
                msgbox = qtw.QMessageBox()
                msgbox.setIcon(qtw.QMessageBox.Information)
                msgbox.setText("Report generated successfully.")
                msgbox.setInformativeText("Do you want to open the report?")
                msgbox.setWindowTitle("Report Generated")
                msgbox.setStandardButtons(qtw.QMessageBox.Open | qtw.QMessageBox.Close)
                reply = msgbox.exec_()
                if reply == qtw.QMessageBox.Open:
                    if system() == "Windows":
                        log.debug("Opening report. (Windows)")
                        os.startfile(report_path) 
                    elif system() == "Linux":
                        log.debug("Opening report. (Linux)")
                        retcode = subprocess.call(('xdg-open', report_path))
                        log.debug(f"Child returned {retcode}")
                    elif system() == "Darwin":
                        log.debug("Opening report. (Darwin)")
                        retcode = subprocess.call(('open', report_path))
                        log.debug(f"Child returned {retcode}")


    def toggle_checkboxes(self):
        """Shows scan options when the custom scan radio button is selected. Hides them otherwise"""
        show = False
        if self.customScanRadioButton.isChecked():
            show = True

        # Show/Hide SQLi Checkboxes
        self.sqliCheckBox.setVisible(show)
        self.sqlTimeCheckBox.setVisible(show)
        # If the checkbox is not checked, disable the time-based checkbox
        if not self.sqliCheckBox.isChecked():
            self.sqlTimeCheckBox.setDisabled(True)
        else:
            self.sqlTimeCheckBox.setDisabled(False)

        # Show/Hide XSS Checkboxes
        self.xssCheckBox.setVisible(show)
        self.domCheckBox.setVisible(show)
        # If the checkbox is not checked, disable the DOM-based checkbox
        if not self.xssCheckBox.isChecked():
            self.domCheckBox.setDisabled(True)
        else:
            self.domCheckBox.setDisabled(False)

        # Show/Hide CI Checkboxes
        self.ciCheckBox.setVisible(show)
        self.ciTimeCheckBox.setVisible(show)
        # If the checkbox is not checked, disable the time-based checkbox
        if not self.ciCheckBox.isChecked():
            self.ciTimeCheckBox.setDisabled(True)
        else:
            self.ciTimeCheckBox.setDisabled(False)

        # Show/Hide data and version Checkboxes
        self.dataCheckBox.setVisible(show)
        self.versionCheckBox.setVisible(show)


    def closeEvent(self, e):
        if self.scanButton.text() == "Stop" or self.scanButton.text() == "Stopping...":
            # A scan is still in progress
            reply = qtw.QMessageBox.question(self, 
                                            "Scan in progress", 
                                            "A scan is still in progress. Do you really want to cancel it and quit?"
                                            )
            if reply == qtw.QMessageBox.Yes:
                # Exit
                # Hide the main window
                self.hide()
                self.stop_threads = True
                if self.alive_thread_count == 0:
                    e.accept()
                # Wait 10 seconds then terminate
                sleep(5)
                if self.alive_thread_count == 0:
                    e.accept()
                sleep(5)
                e.accept()
                
            elif reply == qtw.QMessageBox.No:
                # Return
                e.ignore()
            else:
                # Should never be reached
                e.accept()
        else:
            # No scan in running. Exit
            e.accept()

def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    # Enable log messages in terminal
    logging.basicConfig(
        level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', datefmt='%H:%M:%S')
    run()
