import requests
from urllib.request import urlparse, urljoin
from bs4 import BeautifulSoup
# import colorama

# init the colorama module
# colorama.init()

# GREEN = colorama.Fore.GREEN
# GRAY = colorama.Fore.LIGHTBLACK_EX
# RESET = colorama.Fore.RESET

# initialize the set of links (unique links)
all_urls = set()

# total_urls_visited = 0


def is_valid(url):
    """
    Checks whether `url` is a valid URL.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def get_links(session, url):
    """
    Returns all URLs that is found on `url` in which it belongs to the same website
    """
    # all URLs of `url`
    urls = set()
    # domain name of the URL without the protocol
    domain_name = urlparse(url).netloc
    soup = BeautifulSoup(session.get(url).content, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            # href empty tag
            continue
        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        # print(href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            # not a valid URL
            print(f"[WW] not valid: {href} ")
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
        # print(f"[*] {href}")
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
    # global total_urls_visited
    # total_urls_visited += 1
    links = get_links(session, url)
    # print(f"LINKS {links}")
    for link in links:
        crawl(session, link)

def get_all_links(session, url):
    crawl(session, url)
    return all_urls
    
if __name__ == "__main__":
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
    url = "http://dvwa-win10/vulnerabilities/sqli/"
    # max_urls = 50

    crawl(session, url)

    print("[+] Total:", len(all_urls))

    domain_name = urlparse(url).netloc
    print(domain_name)


    # save the internal links to a file
    # with open(f"{domain_name}_internal_links.txt", "w") as f:
    #     for internal_link in internal_urls:
    #         print(internal_link.strip(), file=f)

    # # save the external links to a file
    # with open(f"{domain_name}_external_links.txt", "w") as f:
    #     for external_link in external_urls:
    #         print(external_link.strip(), file=f)