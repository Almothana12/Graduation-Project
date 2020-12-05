#!/usr/bin/env python3
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
        --fullscan                 Runs a full scan on the URL. Scans with DOM and time-based method, and more payloads.
        --gui                      Start the graphical interface
    -h, --help                     Show this screen
        --html                     Generate an HTML report
        --dom                      Scan for DOM-based XSS
        --time-based               Scan using time-based method
        --pdf                      Generate a PDF report
    -S, --sqli                     Scan for SQLi
        --time=<seconds>           The seconds to inject in time-based TODO
        --verbose                  Show more info
    -v, --version                  Show the version
    -V, --versions                 Scan for the server version
    -X, --xss                      Scan for XSS
"""
import logging
from datetime import datetime

import requests

import command_injection
import data
import gui
import sqli
import versions
import xss
from docopt import docopt
from report import report_generator
from utils.crawler import get_all_links
from utils.logformatter import start_logging
from utils.url_vaildator import valid_url

session = requests.Session()
session.headers['Cookie'] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"


def main():
    # get the command line arguments
    args = docopt(__doc__)

    if args['--verbose']:
        # Show DEBUG level logs
        start_logging(log_level="DEBUG")
    else:
        # Don't show DEBUG level logs 
        start_logging(log_level="INFO")

    # If the GUI option is specified or no option is specified
    if args['--gui'] or all(not x for x in args.values()):
        logging.info("Launching GUI...")
        gui.run()
        return

    # Get the starting datetime without microseconds
    report_generator.start_time = datetime.now().replace(microsecond=0)
    
    url = ""
    if args['<url>']:
        # if the URL doesn't start with http
        if not args['<url>'].startswith("http"):
            # Add http:// to the begining to the URL
            url = "http://" + args['<url>']
        else:
            url = args['<url>']
        # Add the URL to the report
        report_generator.url = url
    else:
        # Should never be reached
        logging.critical("No URL to scan. Exiting...")
        return
    if args['--cookie']:
        session.headers['Cookie'] = args['--cookie']

    # Check if the URL is valid and reachable
    if not valid_url(url, session):
        return

    # List containing all urls to scan
    urls = []
    if args['--crawl']:
        # Get all the URLs in the website
        urls = get_all_links(session, url)
        report_generator.pages_count = len(urls)
        if len(urls) > 1:
            logging.info(f"Scanning {len(urls)} pages")
    else:
        # Scan only one URL
        urls.append(url)
        report_generator.pages_count = 1

    scan_all = False
    # If user didn't specify a vlunerability
    if (not args['--data'] and not args['--versions'] 
    and not args['--sqli'] and not args['--xss'] 
    and not args['--command-injection']):
        # Scan for all vulnerabilities
        scan_all = True

    # Runs a full scan on the URL
    fullscan = args['--fullscan']
    # Scan for SQLi and CI using Time-based method?
    use_time_based = args['--time-based'] or fullscan
    # Scan for XSS using DOM-based method?
    use_dom = args['--dom'] or fullscan

    if args['--versions'] or scan_all:
        versions.check(session, url)
    for url in urls:
        logging.debug(f"Scanning {url}")
        if args['--data'] or scan_all:
            data.check(session, url)
        if args['--sqli'] or scan_all:
            sqli.check(session, url, use_time_based, fullscan)
        if args['--xss'] or scan_all:
            xss.check(session, url, use_dom, fullscan)
        if args['--command-injection'] or scan_all:
            command_injection.check(session, url, use_time_based)

    # Get the datetime without microseconds
    report_generator.finish_time = datetime.now().replace(microsecond=0)
    if args["--html"] or args["--pdf"]:
        # Generate a report
        report_generator.generate_report(html=args["--html"], pdf=args["--pdf"])

    # close the requests session
    session.close()
    # Close the browser
    xss.quit()

if __name__ == "__main__":
    main()
