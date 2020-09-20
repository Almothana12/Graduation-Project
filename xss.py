import HTMLParser
import logging
from urllib.parse import unquote_plus

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

import logformatter

log = logging.getLogger(__name__)

def check_dom_xss(url: str):
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
    # webdriver.firefox.options.headless = True
    # fireFoxOptions.set_headless()
    browser = webdriver.Chrome(options=options)

    # print(url)
    browser.get(url)
    browser.add_cookie(
        {"name": "PHPSESSID", "value": "2r5bfcokovgu1hjf1v08amcd1g"})
    browser.get(url)
    exploitDetected = browser.execute_script("return window.exploitDetected")
    browser.quit()
    log.debug(f"Finished checking DOM XSS")
    if exploitDetected:
        return True
    else:
        return False


def check(session: requests.Session, url: str) -> bool:
    """Check `url` for XSS vulnerability

    Args:
        session (requests.Session): A session object
        url (str): The URL for the page

    Returns:
        bool: True if XSS detected, False otherwise
    """

    forms = HTMLParser.get_all_forms(session, url)
    vulnerable = False

    # Check for DOM XSS first
    dom_payload = "<SCrIpT>window.exploitDetected=true</ScRiPt>"
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        response = HTMLParser.submit_form(form_details, url, dom_payload, session)
        dom_url = unquote_plus(response.url)
        vulnerable = check_dom_xss(dom_url)
    if vulnerable:
        log.warning(f"DOM-based XSS detected on {response.url}")
        log.info(f"payload used: {dom_payload}")
        if form_details['name']:
            log.info(f"Form name: {form_details['name']}")
        return True
    # if no DOM XSS detected, check for reflected:
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("XSSPayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")  # remove newline char
                # print(f"Testing:{payload}")
                response = HTMLParser.submit_form(form_details, url, payload, session)
                if payload.lower() in response.text.lower():
                    log.warning(f"XSS Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    if form_details['name']:
                        log.info(f"Form name: {form_details['name']}")
                    vulnerable = True
                    break
    return vulnerable


if __name__ == "__main__":
    url = "http://dvwa-win10/vulnerabilities/xss_d/"
    # url = "https://xss-game.appspot.com/level1/frame"
    # url = "http://www.insecurelabs.org/Task/Rule1"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    check(session, url)
