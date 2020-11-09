import logging

from jinja2 import Environment, FileSystemLoader


log = logging.getLogger(__name__)
pages = []


class Page:

    def __init__(self, url, dict):
        self.sqli = []
        self.xss = []
        self.ci = []
        self.data = []
        self.url = url
        self.append(dict)

    def append(self, dict):
        vuln = dict["vulnerability"]
        if "SQLI" in vuln:
            self.sqli.append(dict)
        elif "XSS" in vuln:
            self.xss.append(dict)
        elif "CI" in vuln:
            self.ci.append(dict)
        elif "Phone" in vuln or "Email" in vuln:
            self.data.append(dict)
        else:
            logging.debug(f'Unkonw vulnerability: {dict["vulnerability"]}')


def add_vulnerability(vulnerability, url, *args, **kwargs):
    dict = {"vulnerability": vulnerability}
    for arg in kwargs:
        dict[arg] = kwargs[arg]

    url_exist = False
    for page in pages:
        if page.url == url:
            url_exist = True
            page.append(dict)
    if not url_exist:
        pages.append(Page(url, dict))


def generate():
    if not pages:
        logging.error("Cannot generate report. No vulnerabilities added.")
        return

    env = Environment(loader=FileSystemLoader('./report/'))
    template = env.get_template("template.html")

    template_vars = {"pages": pages}
    html_out = template.render(template_vars)

    report = open("report/report.html", "w")
    report.write(html_out)
    report.close()


if __name__ == "__main__":
    add_vulnerability("SQLI", "example.com/signup", form="form", payload="pappsd")
    add_vulnerability("SQLI", "example.com/home", form="form", payload="pappsd")
    add_vulnerability("XSS", "example.com/home", form="form", payload="pappsd")
    add_vulnerability("XSS", "example.com/home", form="form", payload="papfdasfpsd")

    generate()
