import HTMLParser
import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests

import logformatter

log = logging.getLogger(__name__)

def is_vulnerable(response: requests.Response, errors) -> bool:
    """Check if the content of the `response` has an SQL error or not

    Args:
        response (requests.Response): A response object

    Returns:
        bool: True if an error is found in the content of `response`, False otherwise
    """
    for error in errors:
        error = error.replace("\n", "")
        if error.lower() in response.text.lower():
            # If an error is found in the HTML page
            return True
    return False


def time_based(session: requests.Session, url: str, time=5) -> bool:
    """Check for SQLi on `url` using time-based method

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    forms = HTMLParser.get_all_forms(session, url)
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    average_time = (t1 + t2 + t3) / 3
    expected_time = time + average_time
    error_time = expected_time * 0.2
    log.debug("sqli.time_based: avg=%s, error=%s, expected=%s", average_time, error_time, expected_time)
    vulnerable = False
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("payloads/SQLTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                payload = payload.replace("_TIME_", str(time))
                log.debug("sqli.time_based: Testing: %s", payload)
                response = HTMLParser.submit_form(form_details, url, payload, session)
                if not response:
                    continue
                elapsed_time = response.elapsed.total_seconds()
                log.debug(f"sqli.time_based: elapsed={elapsed_time}")
                if expected_time - error_time <= elapsed_time <= expected_time + error_time:
                    log.warning(f"Time-based SQLi Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    vulnerable = True
    return vulnerable


def check(session: requests.Session, url: str, sig=None, stop=None) -> bool:
    """Check for SQLi vulnerability on `url`

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        check_timed (bool): If true, will check of time-based SQLi 

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    payloads = open("payloads/SQLPayloads")
    errors = open("payloads/SQLIErrors")

    vulnerable = False
    forms = HTMLParser.get_all_forms(session, url)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        for payload in payloads:
            if stop:
                if stop():
                    payloads.close()
                    errors.close()
                    sig.finished.emit()
                    return
            if payload.startswith('#'):  # Comment
                continue
            payload = payload.replace("\n", "")  # remove newline char
            # print(f"Testing: {url}")
            response = HTMLParser.submit_form(form_details, url, payload, session)
            if not response:
                continue
            if is_vulnerable(response, errors):
                log.warning(f"SQLi Detected on {response.url}")
                try:
                    log.info(f"Form name: {form['name']}")
                except KeyError:
                    pass
                log.info(f"Payload: {payload}")
                vulnerable = True
                break
    payloads.close()
    errors.close()
    if sig:
        sig.finished.emit()
    return vulnerable


if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    url = "http://dvwa-win10/vulnerabilities/sqli/"
    # time_based(session, url)
    check(session, url)
