"""Scan a website for common web vulnerabilites

Usage:
    main.py
    main.py [options] <url>
    main.py (-h | --help)
    main.py (-v | --version)
Options:
    -c, --cookie=<cookie>          Send this Cookie with the requests
    -C, --command-injection        Check for command injection
        --crawl                    Check for all URLs
    -D, --data                     Check for sensitve data
        --gui                      Start the graphical interface
    -h, --help                     Show this screen
        --no-dom                   Don't check for DOM-based XSS
        --no-time-based            Don't Check using time-based method.
    -S, --sqli                     Check for SQLi
        --time=<seconds>           The seconds to inject in time-based TODO
    -v, --version                  Show the version
    -V, --versions                 Check for the server version
    -X, --xss                      Check for XSS
"""
import logging
import sys
import requests

import command_injection
import report_generator
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
session.headers['Cookie'] = "PHPSESSID=ctgd2jigvorbntt2hfm4o7sltm; security=low"


def main():
    args = docopt(__doc__)

    if args['--gui'] or all(not x for x in args.values()):
        print("Launching GUI...")
        gui.run()
        return
    print(args)
    logformatter.start_logging()
    url = ""
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
    checked = False
    if args['--versions']:
        versions.check(session, url)
        checked = True
    if args['--data']:
        data.check(session, url)
        checked = True
    if args['--sqli']:
        check_time_based = not args['--no-time-based']
        sqli.check(session, url, check_time_based)
        checked = True
    if args['--xss']:
        check_dom = not args['--no-dom']
        xss.check(session, url, check_dom)
        checked = True
    if args['--command-injection']:
        check_time_based = not args['--no-time-based']
        command_injection.check(session, url, check_time_based)
        checked = True
    # If user didn't specify a vlunerability, check for all vulnerabilities
    if not checked:
        # Check for all vulnerabilities
        versions.check(session, url)

        data.check(session, url)

        check_time_based = not args['--no-time-based']
        sqli.check(session, url, check_time_based)

        check_dom = not args['--no-dom']
        xss.check(session, url, check_dom)

        command_injection.check(session, url, check_time_based)
    
    report_generator.generate()
    session.close()


def crawl(url, args):
    urls = get_all_links(session, url)
    checked = False
    if args['--versions']:
        versions.check(session, url)
        checked = True
    for url in urls:
        if args['--data']:
            data.check(session, url)
            checked = True
        if args['--sqli']:
            check_time_based = not args['--no-time-based']
            sqli.check(session, url, check_time_based)
            checked = True
        if args['--xss']:
            check_dom = not args['--no-dom']
            xss.check(session, url, check_dom)
            checked = True
        if args['--command-injection']:
            check_time_based = not args['--no-time-based']
            command_injection.check(session, url, check_time_based)
            checked = True
        # If user didn't specify a vlunerability, check for all vulnerabilities
        if not checked:
            data.check(session, url)

            check_time_based = not args['--no-time-based']
            sqli.check(session, url, check_time_based)

            check_dom = not args['--no-dom']
            xss.check(session, url, check_dom)

            command_injection.check(session, url, check_time_based)
        
    report_generator.generate()
    session.close()


def valid_url(url, session):
    """Check if `url` is valid and reachable

    Args:
        url (str): The url to check

    Returns:
        bool: True if `url` is valid and reachable
    """
    # TODO return error codes 
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
