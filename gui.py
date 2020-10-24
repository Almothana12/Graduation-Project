import sys

import requests
from PyQt5 import QtCore as qtc
from PyQt5 import QtWidgets as qtw

import command_injection
import data
import sqli
import versions
import xss
from crawler import get_all_links
from ui_form import Ui_MainWindow

session = requests.Session()
session.headers['Cookie'] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

class MainWindow(qtw.QMainWindow, Ui_MainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        self.scanButton.clicked.connect(self.scan)

    def scan(self):
        # self.textBrowser.clear()

        url = self.urlLineEdit.text()
        cookie = self.cookieLineEdit.text()
        check_xss = self.xssCheckBox.isChecked()
        check_sqli = self.sqliCheckBox.isChecked()
        check_ci = self.ciCheckBox.isChecked()
        check_version = self.versionCheckBox.isChecked()
        check_data = self.dataCheckBox.isChecked()
        if url:
            if not url.startswith("http"):
                url = "http://" + url
        else:
            qtw.QMessageBox.critical(self, 'Fail', 'No URL Entered')
            return
        if cookie:
            session.headers['Cookie'] = cookie

        # if not valid_url(url):
        #     return

        # if args['--crawl']:
        #     crawl(url, args)
        #     return
        if check_version:
            versions.check(session, url)
            output = open('logs/info.log')
            self.textBrowser.setPlainText(output.read())    
        if check_data:
            data.check(session, url)
            output = open('logs/info.log')
            self.textBrowser.setPlainText(output.read()) 
        if check_sqli:
            sqli.check(session, url)
            output = open('logs/info.log')
            self.textBrowser.setPlainText(output.read())    
            # if not args['--no-time-based']:
            #     sqli.time_based(session, url)
        if check_xss:
            # dom = not args['--no-dom']
            # cookie = args['--cookie']
            xss.check(session, url, True, cookie)
            output = open('logs/info.log')
            self.textBrowser.setPlainText(output.read())     
        if check_ci:
            vulnerable = command_injection.check(session, url)
            output = open('logs/info.log')
            self.textBrowser.setPlainText(output.read())   
            if not vulnerable:
                command_injection.time_based(session, url)
                output = open('logs/info.log')
                self.textBrowser.setPlainText(output.read()) 

        # output = open('logs/test.log')
        output = open('logs/info.log')
        self.textBrowser.setPlainText(output.read())
        self.show_popup()
        output.close()
        open('logs/info.log', 'w').close()



    def show_popup(self):
        msg = qtw.QMessageBox()
        msg.setWindowTitle("Scan Complete")
        msg.setText("Scan Complete")
        msg.setIcon(qtw.QMessageBox.Information)
        msg.setStandardButtons(qtw.QMessageBox.Ok)
        msg.exec_()


def run():
    app = qtw.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
    # import sys
    # app = QtWidgets.QApplication(sys.argv)
    # MainWindow = QtWidgets.QMainWindow()
    # ui = Ui_MainWindow()
    # ui.setupUi(MainWindow)
    # MainWindow.show()
    # sys.exit(app.exec_())


if __name__ == "__main__":
    run()