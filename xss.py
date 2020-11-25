import logging
import sys
import os
from http.cookies import SimpleCookie
from urllib.parse import unquote_plus

import requests
from msedge.selenium_tools import Edge, EdgeOptions  # msedge-selenium-tools
from PyQt5.QtCore import QFile
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

import payloads
from report.report_generator import add_vulnerability
from utils.HTMLParser import get_all_forms, get_form_details, submit_form

log = logging.getLogger(__name__)

browser = None

def init_browser(url: str, str_cookie=None):
    global browser
    if browser:
        # Browser is already initilized
        return browser
    # Initilize the browser
    if (sys.platform == "win32"):
        # If on Windows
        try:
            # Try the Chrome webdriver
            options = ChromeOptions()
            # Add options for imporved performance
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            # Run in headless mode
            options.add_argument("--headless")
            # Hide log message
            options.add_experimental_option('excludeSwitches', ['enable-logging'])
            # Get the webdriver
            browser = webdriver.Chrome(executable_path="webdrivers/chromedriver.exe", options=options)
            # Test if Chrome binary exist
            browser.get(url)
            log.debug("initialized Chrome Driver")
        except:
            log.debug("Failed to set-up Chrome webdriver")
            # Else, try the MS Edge webdriver
            try:
                edge_options = EdgeOptions()
                edge_options.use_chromium = True
                # Run in headless mode
                edge_options.add_argument('headless')
                edge_options.add_argument('disable-gpu')
                # Get the webdriver
                browser = Edge(executable_path="webdrivers/msedgedriver.exe", options=edge_options)
                log.debug("initialized Edge Driver")
            except:
                log.error("Could not set-up a webdriver")
                log.debug("Chrome or Chromium Edge must be installed to scan for DOM-based XSS vulnerability")
                return None
    else:
        # *nix
        try:
            options = FirefoxOptions()
            # Run in headless mode
            options.add_argument("--headless")
            # Get the webdriver
            try:
                browser = webdriver.Firefox(options=options)
            except:
                log.debug("geckodriver is not in PATH")
                browser = webdriver.Firefox(executable_path="webdrivers/geckodriver", options=options)
            # Test if Firefox binary exist
            browser.get(url)
            log.debug("initialized Firefox Driver")
        except:
            log.error("Could not set-up a webdriver")
            log.exception("Firefox must be installed to scan for DOM-based XSS vulnerability")
            return None


    if str_cookie:
        cookie = SimpleCookie()
        cookie.load(str_cookie)
        cookies = {}
        for key, morsel in cookie.items():
            cookies[key] = morsel.value
        browser.get(url)
        # browser.delete_all_cookies()
        for key in cookies.keys():
            value = cookies[key]
            browser.add_cookie({"name": key, "value": value})
    return browser

def check_dom(url: str, str_cookie=None):
    """Check `url` for DOM-Based XSS

    Args:
        url (str): The URL of the page.
        str_cookie (str): A Cookie string.

    Returns:
        bool: True if DOM-Based XSS found, False if not.
    """
    browser = init_browser(url, str_cookie)
    if not browser:
        return False
    browser.get(url)
    exploitDetected = browser.execute_script("return window.exploitDetected")
    if exploitDetected:
        return True
    else:
        return False


def check(session: requests.Session, url: str, dom=True, fullscan=False, sig=None, stop=None) -> bool:
    """Check `url` for XSS vulnerability

    Args:
        session (requests.Session): A session object
        url (str): The URL for the page

    Returns:
        bool: True if XSS detected, False otherwise
    """
    forms = get_all_forms(session, url)
    vulnerable = False
    if stop:
        if stop():
            sig.finished.emit()
            return
    # Check for DOM XSS
    if dom:
        dom_payload = "<SCrIpT>window.exploitDetected=true</ScRiPt>"
        for form in forms:
            form_details = get_form_details(form)
            response = submit_form(form_details, url, dom_payload, session)
            if not response:
                continue
            dom_url = unquote_plus(response.url)
            try:
                vulnerable = check_dom(dom_url, session.headers['Cookie'])
            except KeyError:
                vulnerable = check_dom(dom_url, None)
        if vulnerable:
            
            log.critical(f"DOM-based XSS detected on {response.url}")
            log.info(f"payload used: {dom_payload}")
            if 'name' in form_details:
                add_vulnerability("DOM-XSS", url, form=form_details['name'], payload=dom_payload)
                log.info(f"Form name: {form_details['name']}")
            else:
                add_vulnerability("DOM-XSS", url, form="None", payload=dom_payload)
            if sig:
                sig.finished.emit()
            return True
    # Open the XSS payloads file
    if fullscan:
        payloads_file = QFile(":/XSSPayloads-full")
    else:
        payloads_file = QFile(":/XSSPayloads-quick")
    payloads_file.open(QFile.ReadOnly)
    payloads = bytes(payloads_file.readAll()).decode('utf-8')
    payloads = payloads.splitlines()

    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            if stop:
                if stop():
                    payloads_file.close()
                    sig.finished.emit()
                    return
            # Ignore comment
            if payload.startswith('#'):
                continue
            # remove newline char
            payload = payload.replace("\n", "")
            response = submit_form(form_details, url, payload, session)
            if not response:
                continue
            if payload.lower() in response.text.lower():
                log.critical(f"XSS Detected on {response.url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("XSS", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("XSS", url, form="None", payload=payload)
                vulnerable = True
                break
    payloads_file.close()
    if sig:
        sig.finished.emit()
    return vulnerable

def quit():
    """Close the browser. 
    This should be called after checking for DOM-based XSS
    """
    global browser
    if browser:
        browser.quit()
        browser = None
