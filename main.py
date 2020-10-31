usage = """
Scan a website for common web vulnerabilites

Usage:
    main.py
    main.py [options] <url>
    main.py (-h | --help)
    main.py (-v | --version)
Options:
    -c, --cookie=<cookie>          Send a Cookie with the requests
    -C, --command-injection        Check for command injection
        --crawl                    Check for all URLs
    -D, --data                     Check for sensitve data
        --gui                      Start a graphical interface
    -h, --help                     Show this screen
        --no-dom                   Don't check for DOM-based XSS
    -S, --sqli                     Check for SQLi
        --no-time-based            Don't Check using time-based method.
    -v, --version                  Show the version
    -V, --versions                 Check for the server version
    -X, --xss                      Check for XSS
"""
import logging
import sys
import requests

import command_injection
import data
import logformatter
import sqli
from crawler import get_all_links
import versions
from docopt import docopt
import xss
import gui

session = requests.Session()
# session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers['Cookie'] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"


def main():
    args = docopt(usage)

    if args['--gui'] or all(not x for x in args.values()):
        logformatter.start_logging(console_file="logs/info.log")
        print("Launching GUI...")  # TODO GUI
        gui.run()
        return
    else:
        logformatter.start_logging(console_file="stdout")

    if args['<url>']:
        if not args['<url>'].startswith("http"):
            url = "http://" + args['<url>']
        else:
            url = args['<url>']
    if args['--cookie']:
        session.headers['Cookie'] = args['--cookie']

    if not valid_url(url, session):
        return

    if args['--crawl']:
        crawl(url, args)
        return
    d = False
    if args['--versions']:
        versions.check(session, url)
        d = True
    if args['--data']:
        data.check(session, url)
        d = True
    if args['--sqli']:
        vulnerable = sqli.check(session, url)
        if not args['--no-time-based'] and not vulnerable:
            sqli.time_based(session, url)
        d = True
    if args['--xss']:
        dom = not args['--no-dom']
        cookie = args['--cookie']
        xss.check(session, url, dom, cookie)
        d = True
    if args['--command-injection']:
        vulnerable = command_injection.check(session, url)
        if not vulnerable:
            command_injection.time_based(session, url)
        d = True
    # If user didn't specify a vlunerability, check for all vulnerabilities
    if not d:
        # Check for all vulnerabilities
        versions.check(session, url)

        data.check(session, url)

        sqli.check(session, url)

        dom = not args['--no-dom']
        cookie = args['--cookie']
        xss.check(session, url, dom, cookie)

        vulnerable = command_injection.check(session, url)
        if not vulnerable:
            command_injection.time_based(session, url)

    session.close()


def crawl(url, args):
    urls = get_all_links(session, url)
    d = False
    if args['--versions']:
        versions.check(session, url)
        d = True
    for url in urls:
        if args['--data']:
            data.check(session, url)
            d = True
        if args['--sqli']:
            sqli.check(session, url)
            d = True
        if args['--xss']:
            dom = not args['--no-dom']
            cookie = args['--cookie']
            xss.check(session, url, dom, cookie)
            d = True
        if args['--command-injection']:
            command_injection.check(session, url)
            command_injection.time_based(session, url)
            d = True
        # If user didn't specify a vlunerability, check for all vulnerabilities
        if not d:
            data.check(session, url)

            # sqli.check(session, url)
            sqli.time_based(session, url)

            dom = not args['--no-dom']
            cookie = args['--cookie']
            xss.check(session, url, dom, cookie)

            command_injection.check(session, url)
            command_injection.time_based(session, url)
        
        session.close()


def valid_url(url, session):
    """Check if the `url` is valid and reachable

    Args:
        url (str): The url to check

    Returns:
        bool: True if the `url` is valid
    """
    try:
        response = session.get(url)
        if response.history:
            logging.warning(f"Redirected to {response.url}")
        # raise an HTTPError if the request is unsuccessful
        response.raise_for_status() 
    except requests.ConnectionError as err:
        logging.debug(err)
        logging.error(f"Could Not Reach URL: {err.request.url}")
        return False
    except requests.HTTPError as err:
        logging.debug(err)
        logging.error(f"URL Returned {err.response.status_code}")
        return False
    except requests.Timeout as err:
        logging.debug(err)
        logging.error("Request Timed Out")
        return False
    return True


if __name__ == "__main__":
    main()
