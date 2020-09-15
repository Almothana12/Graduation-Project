import requests
from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import unquote_plus
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import HTMLParser

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

def scan_xss_dom(url):
    '''
    TODO
    '''
    # payload = "<SCrIpT>window.exploitDetected = true</ScRiPt>"
    # xss_url = url + payload

    # r = session.get(xss_url)
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
    return exploitDetected


if __name__ == "__main__":
    url = "http://dvwa-win10/vulnerabilities/xss_d/"
    # url = "https://xss-game.appspot.com/level1/frame"
    # url = "http://www.insecurelabs.org/Task/Rule1"

    forms = HTMLParser.get_all_forms(url, session)
    is_vulnerable = False

    # Check for DOM XSS first
    dom_payload = "<SCrIpT>window.exploitDetected=true</ScRiPt>"
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        response = HTMLParser.submit_form(form_details, url, dom_payload, session)
        s = unquote_plus(response.url)
        if scan_xss_dom(s):
            is_vulnerable = True
    if is_vulnerable:
        print(f"[+] DOM-based XSS vulnerability detected on {url}")
        print(f"payload used: {dom_payload}")
    else: # if no DOM XSS detected, check for reflected or stored:
        for form in forms:
            form_details = HTMLParser.get_form_details(form)
            with open("XSSPayloads") as payloads:
                for payload in payloads:
                    print(f"Testing:{payload}")
                    response = HTMLParser.submit_form(form_details, url, payload, session)
                    if payload.lower() in response.content.decode().lower():
                        print(f"[+] XSS Detected on {url}")
                        print(f"[+] Payload: {payload}")
                        # print(f"[*] Form details:")
                        # pprint(form_details)
                        is_vulnerable = True
                        # break

    print(is_vulnerable)