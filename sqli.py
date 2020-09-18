# import requests
import re 
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote_plus
import HTMLParser


# session.headers["Cache-Control"] = "no-cache"
# session.headers["Pragma"] = "no-cache"

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""

    with open("SQLIErrors") as SQLIErrors:
        for error in SQLIErrors:
            error = error.replace("\n", "")
            if error.lower() in response.text.lower():
                return True
    return False


def timed_sql(session, url):
    url = "http://dvwa-Win10/vulnerabilities/sqli_blind/"
    forms = HTMLParser.get_all_forms(url, session)
    time = 5
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    avg = (t1 + t2 + t3) / 3
    # print(f"Avg: {avg}")
    expected = time + avg
    error = expected * 0.2
    # print (error)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("SQLTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                # print(f"Testing: {payload}")
                response = HTMLParser.submit_form(form_details, url, payload, session)
                elapsed = response.elapsed.total_seconds()
                # print(elapsed)
                if expected - error <= elapsed <= expected + error:
                    print(f"SQL Injection Detected on {response.url}")
                    print(f"Payload: {payload}")
                    return True
    return False


def check(session, url, check_timed):
    vulnerable = False
    if check_timed:
        vulnerable = timed_sql(session, url)
    if vulnerable:
        return True
    forms = HTMLParser.get_all_forms(url, session)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("SQLPayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")  # remove newline char
                # print(f"Testing: {payload}")
                response = HTMLParser.submit_form(form_details, url, payload, session)
                if is_vulnerable(response):
                    print(f"SQL Injection Detected on {response.url}")
                    print(f"Payload: {payload}")

                    return True

if __name__ == "__main__":
    import requests

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

    url = "http://dvwa-win10/vulnerabilities/sqli/"
    check(session, url, False)

