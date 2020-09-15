import re
import logging
import requests
from colorama import init, Fore, Back, Style

init() # Initialise Colorama

# The oldest supported versions
obsolete_apache = "2.4"  # https://www.rapid7.com/db/vulnerabilities/apache-httpd-obsolete
obsolete_lighttpd = "1.4"  # https://www.rapid7.com/db/vulnerabilities/http-lighttpd-obsolete
obsolete_php = "7.2"  # https://www.php.net/supported-versions.php
obsolete_nginx = "1.18" # https://nginx.org/en/download.html
obsolete_iis = 10

# response = requests.get("http://dvwa-win10")
# response = requests.get("http://dvwa-ubuntu")
response = requests.get("http://192.168.100.66")

print(response.headers)

headers = []
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
# print(headers)

if not headers:
    print("could not get server version info")
    exit # TODO

apache_version = ""
for header in headers:
    match = re.search(r"apache(\S*)", header.lower())
    if match:
        apache_version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1)).group()
        break

php_version = ""
for header in headers:
    match = re.search(r"php(\S*)", header.lower())
    if match:
        php_version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1)).group()
        break

nginx_version = ""
for header in headers:
    match = re.search(r"nginx(\S*)", header.lower())
    if match:
        nginx_version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1)).group()
        break

iis_version = ""
for header in headers:
    match = re.search(r"iis(\S*)", header.lower())
    if match:
        iis_version = re.search(r"\d+\.\d+(\.\d+)*", match.group(1)).group()
        break

if apache_version:
    print(f"Apache version: {apache_version}", end='')
    if apache_version < obsolete_apache:
        print(f"{Fore.RED}  (obsolete){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}  (still supported){Style.RESET_ALL}")

if php_version:
    print(f"PHP version: {php_version}", end='')
    if php_version < obsolete_php:
        print(f"{Fore.RED}  (obsolete){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN} (still supported){Style.RESET_ALL}")

if nginx_version:
    print(f"NginX version: {nginx_version}", end='')
    if nginx_version < obsolete_nginx:
        print(f"{Fore.RED}  (outdated){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN} (still supported){Style.RESET_ALL}")

if iis_version:
    print(f"Microsoft IIS version: {iis_version}", end='')
    if float(iis_version) < obsolete_iis:
        print(f"{Fore.RED}  (outdated){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN} (still supported){Style.RESET_ALL}")