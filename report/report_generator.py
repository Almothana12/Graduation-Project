import logging
import os

import pdfkit
from jinja2 import Environment, FileSystemLoader
from report.Page import Page

log = logging.getLogger(__name__)

# List holds objects of Page class.
# Each object represents a webpage.
# Each object contains the URL of the webpage and lists of the
# detected vulnerabilities in that webpage.
pages = []

# A dictionary containing each detected server version
versions = []

start_time = 0
finish_time = 0

vuln_count = 0
pages_count = 0

url = ""

scan_mode = ""


def add_server_version(name, version, outdated):
    """Add a detected server version to the report.

    Args:
        name (str): The name of the software.
        version (str): The detected version.
        outdated (bool): if the version is outdated or not.
    """
    versions.append({"name":name, "version":version, "outdated":outdated})

def add_vulnerability(vulnerability, url, *args, **kwargs):
    """Add a detected vulnerability to the report.

    Args:
        vulnerability (str): The name of the vulnerability.
        url (str): The URL in which the vulnerability was detected in.
    """
    global vuln_count
    vuln_count += 1
    # A dictionary that contains data about the vulnerability.
    dict = {"vulnerability": vulnerability}
    # Add the given data to the dictionary.
    for arg in kwargs:
        dict[arg] = kwargs[arg]

    # Check if page objects already exist for the given URL.
    for page in pages:
        if page.url == url:
            # Page already exist in the list.
            # Add the new vulnerability to it.
            page.append_vuln(dict)
            break
    else:
        # Page does not exist in list.
        # Make a new Page object and add it to the list.
        pages.append(Page(url, dict))


def generate_report(html=False, pdf=False):
    """Generate an HTML or PDF report of all the detected vulnerabilities.
    Returns the path to the generated report."""
    if not pages:
        logging.error("Cannot generate report. No vulnerabilities found.")
        return None

    global vuln_count

    env = Environment(loader=FileSystemLoader('./report/'))
    if pdf:
        # Use the template designed for PDF
        template = env.get_template("pdf_template.html")
    else:
        # Use the normal template
        template = env.get_template("template.html")

    # Calculate the time it took to complete the scan
    total_time = finish_time - start_time

    info = {"Start Time": start_time, 
            "Finish Time": finish_time, 
            "Total Time": total_time, 
            "Vulnerabilities Found": vuln_count, 
            "Pages Scanned": pages_count,
            "Scan Mode": scan_mode
    }
    # Add the variables to the template.
    template_vars = {"pages": pages, "info": info, "versions":versions, "URL":url}
    html_out = template.render(template_vars)

    filename = "report" # TODO

    # Write the generated HTML to file.
    report = open("report/" + filename + ".html", "w")
    htmlpath = os.path.realpath(report.name)
    log.debug(f"Writing HTML report to: {htmlpath}")
    report.write(html_out)
    report.close()
    if pdf:
        # Convert the HTML file to PDF
        options = {"enable-local-file-access": None, 'quiet': ''}
        pdfpath = os.path.dirname(htmlpath) + "/" + filename + ".pdf"
        log.debug(f"Writing PDF report to: {pdfpath}")
        try:
            pdfkit.from_file(htmlpath, pdfpath, options=options)
        except:
            log.error("Could not generate the PDF report. HTML report is generated instead. wkhtmltopdf is required to generate PDF reports.")
            return htmlpath
        log.info(f"PDF report generated to: {pdfpath}")
        if not html:
            # Remove the HTML file
            log.debug(f"Removing: {htmlpath}")
            os.remove(htmlpath)
        else:
            log.info(f"HTML report generated to: {htmlpath}")
        return pdfpath
    else:
        log.info(f"HTML report generated to: {htmlpath}")
        return htmlpath


if __name__ == "__main__":
    from datetime import datetime
    start_time = datetime(2020,1,2,13,43,20)
    finish_time = datetime(2020,1,2,13,48,32)
    pages_count = 3
    url = "http://example.com"
    add_vulnerability("SQLi", "example.com/home", form="login", payload="' OR '1")
    add_vulnerability("SQLi", "example.com/home", form="search", payload="'")
    add_vulnerability("SQLi", "example.com/home", form="None", payload="'")
    add_vulnerability("XSS", "example.com/home", form="form", payload="papfdasfpsd")
    add_vulnerability("SQLi", "example.com/signup", form="form", payload="pappsd")
    add_vulnerability("SQLi", "example.com/signup", form="form", payload="pappsd")
    add_vulnerability("SQLi", "example.com/signup", form="form", payload="pappsd")
    add_vulnerability("CI", "example.com/signup", form="form", payload="pappsd")

    add_vulnerability("Time-Based SQLi", "example.com/signup", form="form", payload="payload")
    add_vulnerability("Time-Based SQLi", "example.com/signup", form="signup", payload="payload")

    add_server_version("Apache", 2.3, True)
    add_server_version("PHP", 5.3, True)
    # add_server_version("Apache", 2.4, False)

    scan_mode = "Quick Scan"

    generate_report(pdf=False, html=True)
