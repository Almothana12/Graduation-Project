import logging
import re

import requests

from report.report_generator import add_vulnerability

log = logging.getLogger(__name__)


def check(session: requests.Session, url: str, sig=None, stop=None) -> None:
    if stop:
        if stop():
            sig.finished.emit()
            return

    # Get the HTML from the URL
    page = session.get(url).text

    # match a string that starts with '+' then 10-15 numbers:
    phone_regex = r"\b\+\d{10,15}\b"
    # find all matches
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator:
        add_vulnerability("Phone Number", url, data=match.group())
        log.warning(f"phone number found: {match.group()} on {url}")

    if stop:
        if stop():
            sig.finished.emit()
            return

    #Saudi Arabia         
    phone_regex = r"\b05\d{8}\b"
    # find all matches
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator: 
        log.warning(f"phone number found: {match.group()} on {url}")

    #French         
    phone_regex = r"\b((\+)33|0)[1-9](\d{2}){4}\b"
    # find all matches
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator: 
        log.warning(f"phone number found: {match.group()} on {url}")

    if stop:
        if stop():
            sig.finished.emit()
            return
    # UK 
    phone_regex = r"\b\+?(44)?(0|7)\d{9,13}\b"
    # find all matches
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator:
        log.warning(f"phone number found: {match.group()} on {url}")

    if stop:
        if stop():
            sig.finished.emit()
            return     

    # india 
    phone_regex = r"\b(?:(?:\+|0{0,2})91(\s*[\ -]\s*)?|[0]?)?[789]\d{9}|(\d[ -]?){10}\d\b"
    iterator = re.finditer(phone_regex, page) # find all
    # loop through the matches
    for match in iterator:
        log.warning(f"phone number found: {match.group()} on {url}")

    if stop:
        if stop():
            sig.finished.emit()
            return 
    #US
    phone_regex = r"\b(\([0-9]{3}\)|[0-9]{3}-)[0-9]{3}-[0-9]{4}\b"
    # find all matches
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator:
        log.warning(f"phone number found: {match.group()} on {url}")

    if stop:
        if stop():
            sig.finished.emit()
            return 
         
    #Pakistan 
    phone_regex = r"\b(0)((3[0-6][0-9]))(\d{7})\b"
    # find all matche
    iterator = re.finditer(phone_regex, page)
    # loop through the matches
    for match in iterator:
        log.warning(f"phone number found: {match.group()} on {url}")


    if stop:
        if stop():
            sig.finished.emit()
            return 

    # match an Email address:
    email_regex = r"[a-zA-Z0-9\._\-\+]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]+)+"
    # find all matches
    iterator = re.finditer(email_regex, page)
    # loop through the matches
    for match in iterator:
        add_vulnerability("Email", url, data=match.group())
        log.warning(f"email found: {match.group()} on {url}")

    if sig:
        sig.finished.emit()


if __name__ == "__main__":
    url = "http://dvwa-win10/"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

    check(session, url)
