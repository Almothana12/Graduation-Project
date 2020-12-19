import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests
from PyQt5.QtCore import QFile

from payloads import payloads
from report.report_generator import add_vulnerability
from utils.HTMLParser import get_all_forms, get_form_details, submit_form

log = logging.getLogger(__name__)


def time_based(session: requests.Session, url: str, time=5, stop=None) -> bool:
    """Check for SQLi on `url` using time-based method.

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    # Get the payloads
    payloads_file = QFile(":/SQLTimePayloads")
    payloads_file.open(QFile.ReadOnly)
    payloads = bytes(payloads_file.readAll()).decode('utf-8')
    payloads = payloads.splitlines()

    forms = get_all_forms(session, url)
    # Calculate the average round trip time for requests
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    average_time = (t1 + t2 + t3) / 3
    # Expected time when injecting time-based payload is avg + sleep time
    expected_time = time + average_time
    # Error margin is +- 20%
    error_time = expected_time * 0.2
    log.debug("sqli.time_based: avg=%s, error=%s, expected=%s",
              average_time, error_time, expected_time)
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            if stop:
                # check if there is a stop signal
                if stop():
                    payloads_file.close()
                    return False
            payload = payload.replace("\n", "")
            # Replace the payload's "_TIME_" with the actual time
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
                log.critical(f"Time-based SQLi Detected on {url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("Time-Based SQLi", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("Time-Based SQLi", url, form="None", payload=payload)
                payloads_file.close()
                return True
            else:
                # No timeout occurred, check the elapsed time
                elapsed_time = response.elapsed.total_seconds()
                log.debug(f"Elapsed={elapsed_time}")
                if expected_time - error_time <= elapsed_time <= expected_time + error_time:
                    log.critical(f"Time-based SQLi Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    if 'name' in form_details:
                        add_vulnerability("Time-Based SQLi", url, form=form_details['name'], payload=payload)
                        log.info(f"Form name: {form_details['name']}")
                    else:
                        add_vulnerability("Time-Based SQLi", url, form="None", payload=payload)
                    payloads_file.close()
                    return True
    payloads_file.close()
    return False

def _is_vulnerable(response: requests.Response, errors) -> bool:
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


def check(session: requests.Session, url: str, timed=True, fullscan=False, sig=None, stop=None) -> bool:
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
        if time_based(session, url, stop=stop):
            if sig:
                sig.finished.emit()
            return True
    if stop:
        # check if there is a stop signal
        if stop():
            sig.finished.emit()
            return
    # Open the SQL payloads file
    if fullscan:
        payloads_file = QFile(":/SQLPayloads-full")
    else:
        payloads_file = QFile(":/SQLPayloads-quick")
    payloads_file.open(QFile.ReadOnly)
    payloads = bytes(payloads_file.readAll()).decode('utf-8')
    payloads = payloads.splitlines()

    # Open the SQL errors file 
    errors_file = QFile(":/SQLErrors")
    errors_file.open(QFile.ReadOnly)
    errors = bytes(errors_file.readAll()).decode('utf-8')
    errors = errors.splitlines()

    vulnerable = False
    forms = get_all_forms(session, url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            if stop:
                if stop():
                    payloads_file.close()
                    errors_file.close()
                    sig.finished.emit()
                    return
            payload = payload.replace("\n", "")  # remove newline char
            # print(f"Testing: {url}")
            response = submit_form(form_details, url, payload, session)
            if response == None:
                # could not inject payload to form, check next form
                break
            if _is_vulnerable(response, errors):
                log.critical(f"SQLi Detected on {response.url}")
                log.info(f"Payload: {payload}")
                if 'name' in form_details:
                    add_vulnerability("SQLi", url, form=form_details['name'], payload=payload)
                    log.info(f"Form name: {form_details['name']}")
                else:
                    add_vulnerability("SQLI", url, form="None", payload=payload)
                vulnerable = True
                break
    payloads_file.close()
    errors_file.close()
    if sig:
        sig.finished.emit()
    return vulnerable
