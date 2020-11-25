import logging

from jinja2 import Environment, FileSystemLoader


log = logging.getLogger(__name__)

# List holds Page objects.
# Each object represents a webpage.
# Each object contains the URL of the webpage and lists of the
# detected vulnerabilities in that webpage.
pages = []

start_time = 0
finish_time = 0

vuln_count = 0
pages_count = 0

class Page:

    def __init__(self, url, dict):
        self.sqli = []
        self.xss = []
        self.ci = []
        self.data = []
        self.url = url
        self.append(dict)

    def append(self, dict):
        """Add a new vulnerability to the object.

        Args:
            dict (dict): A dictionary containing data about the vulnerability.
        """
        vuln = dict["vulnerability"]
        if "SQLI" in vuln:
            # Add the vulnerabiltiy to the SQLi list.
            self.sqli.append(dict)
        elif "XSS" in vuln:
            # Add the vulnerabiltiy to the XSS list.
            self.xss.append(dict)
        elif "CI" in vuln:
            # Add the vulnerabiltiy to the Command Injection list.
            self.ci.append(dict)
        elif "Phone" in vuln or "Email" in vuln:
            # Add the vulnerabiltiy to the data list.
            self.data.append(dict)
        else:
            logging.debug(f'Unkonw vulnerability: {dict["vulnerability"]}')


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
            page.append(dict)
            break
    else:
        # Page does not exist in list.
        # Make a new Page object and add it to the list.
        pages.append(Page(url, dict))


def generate_report():
    """Generate an HTML report of all the detected vulnerabilities."""
    if not pages:
        logging.error("Cannot generate report. No vulnerabilities found.")
        return

    global vuln_count

    env = Environment(loader=FileSystemLoader('./report/'))
    template = env.get_template("template.html")

    total_time = finish_time - start_time
    info = {"Start Time": start_time, "Finish Time": finish_time, "Total Time": total_time, "Vulnerabilities Found": vuln_count, "Pages Scanned": pages_count, "URL": "http://dvwa-win10"}
    # Add the pages list to the template.
    template_vars = {"pages": pages, "info": info}
    html_out = template.render(template_vars)

    # Write the generated HTML to file.
    report = open("report/report.html", "w")
    report.write(html_out)
    report.close()


if __name__ == "__main__":
    from datetime import datetime
    start_time = datetime(2020,1,2,13,43,20)
    finish_time = datetime(2020,1,2,14,44,32)
    add_vulnerability("SQLI", "example.com/signup", form="form", payload="pappsd")
    add_vulnerability("SQLI", "example.com/home", form="form", payload="pappsd")
    add_vulnerability("XSS", "example.com/home", form="form", payload="pappsd")
    add_vulnerability("XSS", "example.com/home", form="form", payload="papfdasfpsd")

    generate_report()
