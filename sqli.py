import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests

from report.report_generator import add_vulnerability
from utils.HTMLParser import get_all_forms, get_form_details, submit_form

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
    forms = get_all_forms(session, url)
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    average_time = (t1 + t2 + t3) / 3
    expected_time = time + average_time
    error_time = expected_time * 0.2
    log.debug("sqli.time_based: avg=%s, error=%s, expected=%s",
              average_time, error_time, expected_time)
    for form in forms:
        form_details = get_form_details(form)
        with open("payloads/SQLTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                payload = payload.replace("_TIME_", str(time))
                log.debug("sqli.time_based: Testing: %s", payload)
                response = submit_form(form_details, url, payload, session)
                if not response:
                    continue
                elapsed_time = response.elapsed.total_seconds()
                log.debug(f"sqli.time_based: elapsed={elapsed_time}")
                if expected_time - error_time <= elapsed_time <= expected_time + error_time:
                    
                    log.critical(f"Time-based SQLi Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    if 'name' in form_details:
                        add_vulnerability("TIME-SQLI", url, form=form_details['name'], payload=payload)
                        log.info(f"Form name: {form_details['name']}")
                    else:
                        add_vulnerability("TIME-SQLI", url, form="None", payload=payload)
                    return True
                    

def check(session: requests.Session, url: str, timed=True, sig=None, stop=None) -> bool:
    """Check for SQLi vulnerability on `url`

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page
        check_timed (bool): If true, will check of time-based SQLi 

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    if timed:
        # Use time-based method
        if time_based(session, url):
            return True

    vulnerable = False
    payloads = open("payloads/SQLPayloads")
    errors = open("payloads/SQLIErrors")

    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
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
            response = submit_form(form_details, url, payload, session)
            if not response:
                continue
            if is_vulnerable(response, errors):
                log.critical(f"SQLi Detected on {response.url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("SQLI", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("SQLI", url, form="None", payload=payload)
                vulnerable = True
                break
    payloads.close()
    errors.close()
    if sig:
        sig.finished.emit()
    return vulnerable