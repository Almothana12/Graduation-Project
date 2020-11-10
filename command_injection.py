import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests

from utils.HTMLParser import get_all_forms, get_form_details, submit_form
from report.report_generator import add_vulnerability

log = logging.getLogger(__name__)

def is_vulnerable(response: requests.Response) -> bool:
    """Check if the the echo command executed in the server

    Args:
        response (requests.Response): A response object

    Returns:
        bool: True if an error is found in the content of `response`, False otherwise
    """
    if "CommandInjectionDetected" in response.text and "echo" not in response.text  :
        return True
    return False


def time_based(session: requests.Session, url: str, time=10) -> bool:
    """Check if `url` has a Command Injection vulnerability using time-based method

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        time (int, optional): the time to sleep. Defaults to 10.

    Returns:
        bool: True if Command Injection detected, False otherwise
    """
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    avg = (t1 + t2 + t3) / 3
    expected = time + avg
    error = expected * 0.2
    
    log.debug("ci.time_based: avg=%s, error=%s, expected=%s", avg, error, expected)
    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
        with open("payloads/CommandInjectionTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                payload = payload.replace("_TIME_", str(time))
                log.debug("ci.time_based: Testing: %s", payload)
                response = submit_form(form_details, url, payload, session)
                if not response:
                    continue
                elapsed = response.elapsed.total_seconds()
                log.debug(f"ci.time_based: elapsed={elapsed}")
                if expected - error <= elapsed <= expected + error:
                    log.critical(f"Time-based Command Injection Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    if 'name' in form_details:
                        add_vulnerability("TIME-CI", url, form=form_details['name'], payload=payload)
                        log.info(f"Form name: {form_details['name']}")
                    else:
                        add_vulnerability("TIME-CI", url, form="None", payload=payload)
                    return True
    return False


def check(session, url, timed=True, sig=None, stop=None) -> bool:
    """Check for Command Injection vulnerability

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        sig (str): TODO

    Returns:
        bool: True if Command Injection detected, False otherwise
    """
    if timed:
        # Use time-based method
        if time_based(session, url):
            return True
    payloads = open("payloads/CommandInjectionPayloads")
    vulnerable = False
    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
        if stop:
            if stop():
                payloads.close()
                sig.finished.emit()
                return
        for payload in payloads:
            if payload.startswith('#'):  # Ignore comment
                continue
            payload = payload.replace("\n", "")  # remove newline char
            # log.debug(f"ci: Testing: {payload}")
            response = submit_form(form_details, url, payload, session)
            if not response:
                continue
            if is_vulnerable(response):
                log.critical(f"Command Injection found on {response.url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("CI", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("CI", url, form="None", payload=payload)
                vulnerable = True
                break
    payloads.close()
    if sig:
        sig.finished.emit()
    return vulnerable


if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    # url = "http://bee-box/bWAPP/commandi_blind.php"
    url = "http://dvwa-win10/vulnerabilities/exec/"
    check(session, url)
