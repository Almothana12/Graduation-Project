import logging

log = logging.getLogger(__name__)

class Page:

    def __init__(self, url, dict):
        self.url = url
        self.sqli = []
        self.xss = []
        self.ci = []
        self.data = []
        self.append_vuln(dict)

    def append_vuln(self, dict):
        """Add a new vulnerability to the page object.

        Args:
            dict (dict): A dictionary containing data about the vulnerability.
        """
        vuln = dict["vulnerability"]
        if "SQLi" in vuln:
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
