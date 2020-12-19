import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests
from PyQt5.QtCore import QFile

from payloads import payloads
from report.report_generator import add_vulnerability
from utils.HTMLParser import get_all_forms, get_form_details, submit_form

log = logging.getLogger(__name__)

def _is_vulnerable(response: requests.Response) -> bool:
    """Check if the the echo command executed in the server

    Args:
        response (requests.Response): A response object

    Returns:
        bool: True if an error is found in the content of `response`, False otherwise
    """
    if "CommandInjectionDetected" in response.text and "echo" not in response.text  :
        return True
    return False


def time_based(session: requests.Session, url: str, time=10, stop=None) -> bool:
    """Check if `url` has a Command Injection vulnerability using time-based method

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        time (int, optional): the time to sleep. Defaults to 10.

    Returns:
        bool: True if Command Injection detected, False otherwise
    """
    # Open the Command Injection time-based payloads file
    payloads_file = QFile(":/CommandInjectionTimePayloads")
    payloads_file.open(QFile.ReadOnly)
    payloads = bytes(payloads_file.readAll()).decode('utf-8')
    payloads = payloads.splitlines()

    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    avg = (t1 + t2 + t3) / 3
    expected = time + avg
    error = expected * 0.2
    
    log.debug("avg=%s, error=%s, expected=%s", avg, error, expected)
    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            if stop:
                if stop():
                    payloads_file.close()
                    return
            # Remove the newline character
            payload = payload.replace("\n", "")
            # Replace "_TIME_" with the actual time
            payload = payload.replace("_TIME_", str(time))
            log.debug("Testing: %s", payload)

            # Timeout is 150% of sleep time
            timeout = time + (time * 0.5)
            # Submit the form with the injected payload 
            try:
                response = submit_form(form_details, url, payload, session, timeout=timeout)
                if response == None:
                    # could not inject payload to form, check next form
                    break
            except requests.Timeout as e:
                # If timeout occurred, assume time-based SQLi is successful.
                log.debug("Timout occurred")
                log.debug(e)
                log.critical(f"Time-based Command Injection Detected on {url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("TIME-CI", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("TIME-CI", url, form="None", payload=payload)
                payloads_file.close()
                return True
            else:
                # No timeout occurred, check the elapsed time
                elapsed = response.elapsed.total_seconds()
                log.debug(f"Elapsed={elapsed}")
                if expected - error <= elapsed <= expected + error:
                    log.critical(f"Time-based Command Injection Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    if 'name' in form_details:
                        add_vulnerability("TIME-CI", url, form=form_details['name'], payload=payload)
                        log.info(f"Form name: {form_details['name']}")
                    else:
                        add_vulnerability("TIME-CI", url, form="None", payload=payload)
                    payloads_file.close()
                    return True
    payloads_file.close()
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
        if time_based(session, url, stop=stop):
            if sig:
                sig.finished.emit()
            return True
    # Open the Command Injection payloads file
    payloads_file = QFile(":/CommandInjectionPayloads")
    payloads_file.open(QFile.ReadOnly)
    payloads = bytes(payloads_file.readAll()).decode('utf-8')
    payloads = payloads.splitlines()

    vulnerable = False
    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
        if stop:
            if stop():
                payloads_file.close()
                sig.finished.emit()
                return
        for payload in payloads:
            if payload.startswith('#'):  # Ignore comment
                continue
            payload = payload.replace("\n", "")  # remove newline char
            # log.debug(f"ci: Testing: {payload}")
            response = submit_form(form_details, url, payload, session)
            if response == None:
                # could not inject payload to form, check next form
                break
            if _is_vulnerable(response):
                log.critical(f"Command Injection found on {response.url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("CI", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("CI", url, form="None", payload=payload)
                vulnerable = True
                break
    payloads_file.close()
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
