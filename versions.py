import re
import logging
import requests
from packaging.version import parse as parse_version
from colorama import init, Fore, Back, Style

init() # Initialise Colorama

# A dict containing the lastest supported version of each program
versions = {
    "Apache": parse_version("2.4"),   # https://www.rapid7.com/db/vulnerabilities/apache-httpd-obsolete
    "PHP": parse_version("7.2"),      # https://www.php.net/supported-versions.php
    "Lighttp": parse_version("1.4"),  # https://www.rapid7.com/db/vulnerabilities/http-lighttpd-obsolete
    "NginX": parse_version("1.18"),   # https://nginx.org/en/download.html
    "IIS": parse_version("10")
}


# print(response.status_code)

headers = []

# print(headers)




def get_version(name):
    """
        TODO
    """
    for header in headers:
        match = re.search(name.lower() + r"(\S*)", header.lower())
        if match:
            version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1))
            if version:
                return version.group()
        return ""


def print_versions(url):
    response = requests.get(url)
    if 'server' in response.headers:
        headers.append(response.headers['server'])
    if 'x-powered-by' in response.headers:
        headers.append(response.headers['x-powered-by'])
    if 'X-Runtime' in response.headers:
        headers.append(response.headers['X-Runtime'])
    if 'X-Version' in response.headers:
        headers.append(response.headers['X-Version'])
    if 'X-AspNet-Version' in response.headers:
        headers.append(response.headers['X-AspNet-Version'])

    if not headers:
        print("could not get server version info")
        return

    for name, supported_version in versions.items():
        server_version = get_version(name)
        if server_version:
            server_version = parse_version(server_version)
            print(f"{name} version: {server_version}", end='')
            if server_version < supported_version:
                print(f"{Fore.RED}  (outdated){Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}  (still supported){Style.RESET_ALL}")

if __name__ == "__main__":
    url = "http://dvwa-win10"
    # response = requests.get("http://dvwa-ubuntu")
    # response = requests.get("http://centos82")
    # response = requests.get("http://bee-box")
    # response = requests.get("http://windows7")
    # response = requests.get("http://www.insecurelabs.org/Task/Rule1")
    print_versions(url)


