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
import sqli
import versions
import xss
from docopt import docopt
from report.report_generator import generate_report
from utils.crawler import get_all_links
from utils.logformatter import start_logging
from utils.url_vaildator import valid_url

session = requests.Session()
session.headers['Cookie'] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"


def main():
    # get the command line arguments
    args = docopt(__doc__)

    if args['--verbose']:
        # Show INFO level logs
        start_logging(log_level="INFO")
    else:
        # Don't show INFO level logs 
        start_logging(log_level="INFO")
        # logformatter.start_logging(log_level="WARNING") TODO

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
        
    generate_report()
    session.close()

if __name__ == "__main__":
    main()
