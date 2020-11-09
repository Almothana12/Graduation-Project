"""Scan a website for common web vulnerabilites

Usage:
    main.py
    main.py [options] <url>
    main.py (-h | --help)
    main.py (-v | --version)
Options:
    -c, --cookie=<cookie>          Send this Cookie with the requests
    -C, --command-injection        Scan for command injection
        --crawl                    Scan all pages in the website
    -D, --data                     Scan for sensitve data
        --gui                      Start the graphical interface
    -h, --help                     Show this screen
        --no-dom                   Don't Scan for DOM-based XSS
        --no-time-based            Don't Scan using time-based method.
    -S, --sqli                     Scan for SQLi
        --time=<seconds>           The seconds to inject in time-based TODO
        --verbose                  Show more info
    -v, --version                  Show the version
    -V, --versions                 Scan for the server version
    -X, --xss                      Scan for XSS
"""
import logging

import requests

import command_injection
import data
import gui
import logformatter
import report_generator
import sqli
import versions
import xss
from crawler import get_all_links
from docopt import docopt

session = requests.Session()
session.headers['Cookie'] = "PHPSESSID=ctgd2jigvorbntt2hfm4o7sltm; security=low"



def main():
    # get the command line arguments
    args = docopt(__doc__)

    if args['--verbose']:
        # Show INFO level logs
        logformatter.start_logging(log_level="INFO")
    else:
        # Don't show INFO level logs 
        logformatter.start_logging(log_level="WARNING")

    if args['--gui'] or all(not x for x in args.values()):
        logging.info("Launching GUI...")
        gui.run()
        return

    url = ""
    if args['<url>']:
        # if the URL doesn't start with http:// or https://
        if not args['<url>'].startswith(("http://", "https://")):
            # Add http:// to the begining to the URL
            url = "http://" + args['<url>']
        else:
            url = args['<url>']

    if args['--cookie']:
        session.headers['Cookie'] = args['--cookie']

    if not valid_url(url, session):
        return

    # List containing all urls to scan
    urls = []
    if args['--crawl']:
        # Get all the URLs in the website
        urls = get_all_links(session, url)
        if len(urls) > 1:
            logging.info(f"Scanning {len(urls)} pages")
    else:
        # Scan only one URL
        urls.append(url)

    scan_all = False
    # If user didn't specify a vlunerability
    if (not args['--data'] and not args['--versions'] 
    and not args['--sqli'] and not args['--xss'] 
    and not args['--command-injection']):
        # Scan for all vulnerabilities
        scan_all = True

    # Scan for SQLi and CI using Time-based method?
    use_time_based = not args['--no-time-based']
    # Scan for XSS using DOM-based method?
    use_dom = not args['--no-dom']

    if args['--versions'] or scan_all:
        versions.check(session, url)
    for url in urls:
        if args['--data']:
            data.check(session, url)
        if args['--sqli']:
            sqli.check(session, url, use_time_based)
        if args['--xss']:
            xss.check(session, url, use_dom)
        if args['--command-injection']:
            command_injection.check(session, url, use_time_based)
        if scan_all:
            data.check(session, url)
            sqli.check(session, url, use_time_based)
            xss.check(session, url, use_dom)
            command_injection.check(session, url, use_time_based)
        
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
