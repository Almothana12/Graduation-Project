import requests
import re 
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote_plus
from pprint import pprint
import HTMLParser

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


if __name__ == "__main__":
    import sys
    # url = sys.argv[1]
    url = "http://dvwa-win10/vulnerabilities/sqli/"
    forms = HTMLParser.get_all_forms(url, session)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("SQLPayloads") as payloads:
            for payload in payloads:
                print(f"Testing: {payload}")
                response = HTMLParser.submit_form(form_details, url, payload, session)
                print(response.url)
                if is_vulnerable(response):
                    print("TRUE")
                else:
                    print("FALSE")
