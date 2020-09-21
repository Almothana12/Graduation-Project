import HTMLParser
import logging
import re
from urllib.parse import unquote_plus, urljoin

import requests

import logformatter

log = logging.getLogger(__name__)

# def is_vulnerable(response: requests.Response) -> bool:
#     """Check if the content of the `response` has an SQL error

#     Args:
#         response (requests.Response): A response object

#     Returns:
#         bool: True if an error is found in the content of `response`, False otherwise
#     """
#     with open("SQLIErrors") as SQLIErrors:
#         for error in SQLIErrors:
#             error = error.replace("\n", "")
#             if error.lower() in response.text.lower():
#                 return True
#     return False


def time_based(session: requests.Session, url: str, time=10) -> bool:
    """Check if `url` has a Command Injection vulnerability using time-based method

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page

    Returns:
        bool: True if SQLi detected, False otherwise
    """
    time = 10
    t1 = session.get(url).elapsed.total_seconds()
    t2 = session.get(url).elapsed.total_seconds()
    t3 = session.get(url).elapsed.total_seconds()
    avg = (t1 + t2 + t3) / 3
    expected = time + avg
    error = expected * 0.2
    
    log.debug("ci.time_based: avg=%s, error=%s, expected=%s", avg, error, expected)
    forms = HTMLParser.get_all_forms(session, url)
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("payloads/CommandInjectionTimePayloads") as payloads:
            for payload in payloads:
                payload = payload.replace("\n", "")
                payload = payload.replace("_TIME_", str(time))
                log.debug("ci.time_based: Testing: %s", payload)
                response = HTMLParser.submit_form(
                    form_details, url, payload, session)
                elapsed = response.elapsed.total_seconds()
                log.debug(f"ci.time_based: elapsed={elapsed}")
                if expected - error <= elapsed <= expected + error:
                    log.warning(f"Time-based Command Injection Detected on {response.url}")
                    log.info(f"Payload: {payload}")
                    return True
    return False


def check(session: requests.Session, url: str) -> bool:
    """Check for Command Injection vulnerability

    Args:
        session (requests.Session): A Session object
        url (str): The URL of the page

    Returns:
        bool: True if Command Injection detected, False otherwise
    """
    # vulnerable = False
    # if vulnerable:
    #     return True
    # # forms = HTMLParser.get_all_forms(session, url)
    # # for form in forms:
    # #     form_details = HTMLParser.get_form_details(form)
    # #     with open("SQLPayloads") as payloads:
    # #         for payload in payloads:
    # #             payload = payload.replace("\n", "")  # remove newline char
    # #             # print(f"Testing: {payload}")
    # #             response = HTMLParser.submit_form(
    # #                 form_details, url, payload, session)
    # #             if is_vulnerable(response):
    # #                 log.warning(f"SQLi Detected on {response.url}")
    # #                 log.info(f"Payload: {payload}")

    # #                 return True


if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "security_level=0; PHPSESSID=728c89ca46666766646dcaefbf89e888; has_js=1"
    url = "http://bee-box/bWAPP/commandi_blind.php"
    time_based(session, url)
