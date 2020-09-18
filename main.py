import requests
import xss
import sqli
import versions
import data

session = requests.Session()
# session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
url = "http://dvwa-win10/vulnerabilities/sqli/"


def main():
    if not session.get(url):
        print("url error")
        return
    versions.print_versions(url)
    data.check(session, url)
    xss.check(session, url)
    time_sql = False
    sqli.check(session, url, time_sql)


if __name__ == "__main__":
    main()