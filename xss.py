import logging
from http.cookies import SimpleCookie
from urllib.parse import unquote_plus

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from report.report_generator import add_vulnerability
from utils.HTMLParser import get_all_forms, get_form_details, submit_form

log = logging.getLogger(__name__)


def check_dom(url: str, str_cookie=None):
    """Check `url` for DOM-Based XSS

    Args:
        url (str): The URL of the page

    Returns:
        bool: True if DOM-Based XSS found, False otherwise
    """
    log.debug(f"Checking DOM XSS on {url}")

    options = Options()
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")  # linux only
    options.add_argument("--headless")
    try:
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
    except:
        pass
    # webdriver.firefox.options.headless = True
    # fireFoxOptions.set_headless()
    browser = webdriver.Chrome(options=options)

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
    browser.get(url)
    exploitDetected = browser.execute_script("return window.exploitDetected")
    browser.quit()
    log.debug(f"Finished checking DOM XSS")
    if exploitDetected:
        return True
    else:
        return False


def check(session: requests.Session, url: str, dom=True, sig=None, stop=None) -> bool:
    """Check `url` for XSS vulnerability

    Args:
        session (requests.Session): A session object
        url (str): The URL for the page

    Returns:
        bool: True if XSS detected, False otherwise
    """
    payloads = open("payloads/XSSPayloads")
    forms = get_all_forms(session, url)
    vulnerable = False
    if stop:
        if stop():
            payloads.close()
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
    # if no DOM XSS detected, check for reflected or stored:
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            if stop:
                if stop():
                    payloads.close()
                    sig.finished.emit()
                    return
            if payload.startswith('#'):  # Ignore comment
                continue
            payload = payload.replace("\n", "")  # remove newline char
            # log.debug(f"Testing:{url}")
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
    if sig:
        sig.finished.emit()
    return vulnerable