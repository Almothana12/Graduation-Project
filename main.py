import logging
import sys

import requests

import command_injection
import data
import logformatter
import sqli
import versions
import xss

session = requests.Session()
# session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
# session.headers["Cache-Control"] = "no-cache"
# session.headers["Pragma"] = "no-cache"
url = "http://dvwa-win10/vulnerabilities/xss_r/"


def main():
    if not (r:=(session.get(url))):
        logging.critical("Could not reach URL. Status code: %s", r.status_code)
        return
    versions.print_versions(session, url)
    data.check(session, url)
    xss.check(session, url)
    sqli.check(session, url)
    sqli.time_based(session, url)
    command_injection.time_based(session, url)



if __name__ == "__main__":
    main()
