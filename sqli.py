import HTMLParser
import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests

import logformatter

log = logging.getLogger(__name__)

def is_vulnerable(response: requests.Response) -> bool:
    """Check if the content of the `response` has an SQL error

    Args:
        response (requests.Response): A response object

    Returns:
        bool: True if an error is found in the content of `response`, False otherwise
    """
    with open("payloads/SQLIErrors") as SQLIErrors:
        for error in SQLIErrors:
            error = error.replace("\n", "")
            if error.lower() in response.text.lower():
                return True
    return False


def timed_sql(session: requests.Session, url: str) -> bool:
    """Check if `url` has an SQLi vulnerability using time-based method

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    log.debug("timed_sql(%s)", url)
    forms = HTMLParser.get_all_forms(session, url)
    time = 5
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    avg = (t1 + t2 + t3) / 3
    expected = time + avg
    error = expected * 0.2
    log.debug("timed_sql: avg=%s, error=%s, expected=%s", avg, error, expected)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("payloads/SQLTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                log.debug("timed_sql: Testing: %s", payload)
                response = HTMLParser.submit_form(
                    form_details, url, payload, session)
                elapsed = response.elapsed.total_seconds()
                log.debug(f"timed_sql: elapsed={elapsed}")
                if expected - error <= elapsed <= expected + error:
                    log.warning(f"Time-based SQLi Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    # print(f"SQL Injection Detected on {response.url}")
                    # print(f"Payload: {payload}")
                    return True
    return False


def check(session: requests.Session,
          url: str,
          check_timed: bool) -> bool:
    """Check of SQL

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        check_timed (bool): If true, will check of time-based SQLi 

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    log.debug("sqli.check(%s, %s)", url, check_timed)
    vulnerable = False
    if check_timed:
        vulnerable = timed_sql(session, url)
    if vulnerable:
        return True
    forms = HTMLParser.get_all_forms(session, url)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("payloads/SQLPayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")  # remove newline char
                # print(f"Testing: {payload}")
                response = HTMLParser.submit_form(
                    form_details, url, payload, session)
                if is_vulnerable(response):
                    log.warning(f"SQLi Detected on {response.url}")
                    log.info(f"Payload: {payload}")

                    return True


if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    url = "http://dvwa-win10/vulnerabilities/sqli/"
    check(session, url, False)
