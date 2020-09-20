import logging
import re

import requests

import logformatter

log = logging.getLogger(__name__)

def check(session: requests.Session, url: str) -> None:
    page = session.get(url).text

    # match a string of 10 numbers
    # or if it starts with '+' then 10 or more numbers:
    phone_regex = r"(\b\d{10}\b)|(\+\d{10,15}\b)"
    iterator = re.finditer(phone_regex, page) # find all
    for match in iterator: # loop through the matches
        log.warning(f"phone number found: {match.group()}")

    # match an Email address:
    email_regex = r"[a-zA-Z0-9\._\-\+]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]+)+"
    iterator = re.finditer(email_regex, page)
    for match in iterator:
        log.warning(f"email found: {match.group()}")

if __name__ == "__main__":
    url = "http://dvwa-win10/"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

    check(session, url)
