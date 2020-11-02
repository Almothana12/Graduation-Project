import logging
import re

import requests
from colorama import Back, Fore, Style, init
from packaging.version import parse as parse_version

import logformatter

init()  # Initialise Colorama

log = logging.getLogger(__name__)

# A dict containing the lastest supported version of each program
versions = {
    "Apache": parse_version("2.4"),   # https://www.rapid7.com/db/vulnerabilities/apache-httpd-obsolete
    "PHP": parse_version("7.2"),      # https://www.php.net/supported-versions.php
    "Lighttp": parse_version("1.4"),  # https://www.rapid7.com/db/vulnerabilities/http-lighttpd-obsolete
    "NginX": parse_version("1.18"),   # https://nginx.org/en/download.html
    "IIS": parse_version("10")
}

headers = []


def get_version(name: str) -> str:
    """Search for `name` in the HTTP header and return the version of it

    Args:
        name (str): A name of an application

    Returns:
        str: The version of the application, empty string if doesn't exist
    """
    for header in headers:
        match = re.search(name.lower() + r"(\S*)", header.lower())
        if match:
            version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1))
            if version:
                return version.group()
        return ""


def check(session, url, sig=None) -> None:
    """Search and Print the server's version

    Args:
        session (requests.Session): A session object
        url (str): The URL of the server
    """
    response = session.get(url)
    # Fill the headers list
    if 'server' in response.headers:
        log.debug(f"versions: 'server' header found: {response.headers['server']}")
        headers.append(response.headers['server'])
    if 'x-powered-by' in response.headers:
        log.debug(f"versions: 'x-powered-by' header found: {response.headers['x-powered-by']}")
        headers.append(response.headers['x-powered-by'])
    if 'X-Runtime' in response.headers:
        log.debug(f"versions: 'X-Runtime' header found: {response.headers['X-Runtime']}")
        headers.append(response.headers['X-Runtime'])
    if 'X-Version' in response.headers:
        log.debug(f"versions: 'X-Version' header found: {response.headers['X-Version']}")
        headers.append(response.headers['X-Version'])
    if 'X-AspNet-Version' in response.headers:
        log.debug(f"versions: 'X-AspNet-Version' header found: {response.headers['X-AspNet-Version']}")
        headers.append(response.headers['X-AspNet-Version'])

    if not headers:
        log.debug("Could not get server version info")
        if sig:
            sig.finished.emit()
        return
    # Print the found versions 
    version_found = False
    for name, supported_version in versions.items():
        server_version = get_version(name)
        if server_version:
            version_found = True
            server_version = parse_version(server_version)
            if server_version < supported_version:
                log.warning(f"{name} version: {server_version}  {Fore.RED}(outdated){Style.RESET_ALL}")
            else:
                log.info(f"{name} version: {server_version}")
    if version_found:
        log.warning("version found")  # TODO write a helpful message
    else:
        log.debug("Could not get server version info")

    if sig:
        sig.finished.emit()

if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    url = "http://dvwa-win10"
    # url = "http://dvwa-ubuntu"
    # url = "http://centos82"
    # url = "http://bee-box"
    # url = "http://windows7"
    # url = "http://www.insecurelabs.org/Task/Rule1"
    check(session, url)
