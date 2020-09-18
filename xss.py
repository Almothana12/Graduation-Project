# import requests
# from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import unquote_plus
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import HTMLParser

def scan_xss_dom(url):
    '''
    TODO
    '''
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


def check(session, url):
    """

    """
    forms = HTMLParser.get_all_forms(url, session)
    vulnerable = False

    # Check for DOM XSS first
    dom_payload = "<SCrIpT>window.exploitDetected=true</ScRiPt>"
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        response = HTMLParser.submit_form(form_details, url, dom_payload, session)
        dom_url = unquote_plus(response.url)
        vulnerable = scan_xss_dom(dom_url)
    if vulnerable:
        print(f"DOM-based XSS detected on {response.url}")
        print(f"payload used: {dom_payload}")
        return True
    # if no DOM XSS detected, check for reflected:
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("XSSPayloads") as payloads:
            for payload in payloads:
                # print(f"Testing:{payload}")
                response = HTMLParser.submit_form(form_details, url, payload, session)
                if payload.lower() in response.text.lower():
                    print(f"XSS Detected on {response.url}")
                    print(f"Payload: {payload}")
                    # print(f"[*] Form details:")
                    # pprint(form_details)
                    vulnerable = True
                    break
    return vulnerable


if __name__ == "__main__":
    import requests
    url = "http://dvwa-win10/vulnerabilities/xss_d/"
    # url = "https://xss-game.appspot.com/level1/frame"
    # url = "http://www.insecurelabs.org/Task/Rule1"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    check(session, url)
