import requests
from urllib.request import urlparse, urljoin
from bs4 import BeautifulSoup
import logging

log = logging.getLogger(__name__)

# initialize the set of links (unique links)
all_urls = set()


def is_valid(url):
    """
    Check whether `url` is a valid URL.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def get_links(session, url):
    """
    Return all URLs that is found on `url` in which it belongs to the same website
    """
    # all URLs of `url`
    urls = set()
    # domain name of the URL without the protocol (http://)
    domain_name = urlparse(url).netloc
    soup = BeautifulSoup(session.get(url).content, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if not href:
            # href empty tag
            continue
        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            # not a valid URL
            logging.debug(f"not valid href: {href} ")
            continue
        if "logout" in href:
            # Don't logout
            continue
        if href in all_urls:
            # already in the set
            continue
        if domain_name not in href:
            # external link
            continue
        urls.add(href)
        all_urls.add(href)
    return urls


def crawl(session, url):
    """
    Crawls a web page and extracts all links.
    You'll find all links in `external_urls` and `internal_urls` global set variables.
    params:
        max_urls (int): number of max urls to crawl, default is 30.
    """

    links = get_links(session, url)
    for link in links:
        crawl(session, link)


def get_all_links(session, url):
    crawl(session, url)
    return all_urls


if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    # session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    url = "http://testphp.vulnweb.com/"

    crawl(session, url)

    for url in all_urls:
        print(url)
    print("Total urls:", len(all_urls))
