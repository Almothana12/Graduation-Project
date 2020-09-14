import HTMLParser
import requests
import re
from pprint import pprint
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, unquote_plus
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
# login_payload = {
#     "username": "admin",
#     "password": "password",
#     "Login": "Login",
# }
# login_url = "http://dvwa-win10/login.php"

# # login:
# response = session.get(login_url)
# #pprint(response.headers)
# token = re.search(r"user_token'\s*value='(.*?)'", response.text).group(1)
# login_payload['user_token'] = token
# session.post(login_url, data=login_payload)
# cookies = {'PHPSESSID': '2r5bfcokovgu1hjf1v08amcd1g'}

# def get_all_forms(url):
#     """Given a `url`, it returns all forms from the HTML content"""
#     soup = BeautifulSoup(session.get(url).content, "html.parser")
#     return soup.find_all("form")

# def get_form_details(form):
#     """
#     This function extracts all possible useful information about an HTML `form`
#     """
#     details = {}
#     # pprint(form)
#     # get the form action
#     action = form.attrs.get("action")#.lower()
#     # get the form method
#     method = form.attrs.get("method", "get").lower()
#     # get all the input details such as type and name
#     inputs = []
#     for input_tag in form.find_all("input"):
#         input_type = input_tag.attrs.get("type", "text")
#         input_name = input_tag.attrs.get("name")
#         inputs.append({"type": input_type, "name": input_name})

#     selects = []
#     for select_tag in form.find_all("select"):
#         select_type = select_tag.attrs.get("type", "text")
#         select_name = select_tag.attrs.get("name")
#         selects.append({"type": select_type, "name": select_name})
#     # put everything to the resulting dictionary
#     details["action"] = action
#     details["method"] = method
#     details["inputs"] = inputs
#     details["selects"] = selects

#     return details


# def submit_form(form_details, url, value):
#     """
#     Submits a form given in `form_details`
#     Params:
#         form_details (list): a dictionary that contain form information
#         url (str): the original URL that contain that form
#         value (str): this will be replaced to all text and search inputs
#     Returns the HTTP Response after form submission
#     """
#     # construct the full URL (if the url provided in action is relative)
#     target_url = urljoin(url, form_details["action"])
#     # target_url = url
#     data = {} # the data to be submitted

#     # get the inputs from the form
#     for input in form_details["inputs"]:
#         # replace all text and search values with `value`
#         if input["type"] == "text" or input["type"] == "search":
#             input["value"] = value

#         input_name = input.get("name")
#         input_value = input.get("value")
#         if input_name and input_value:
#             # if input name and value are not None,
#             # then add them to the data of form submission

#             data[input_name] = input_value

#     for select in form_details["selects"]:
#         if select["type"] == "text":
#             select["value"] = value
#         select_name = select.get("name")
#         select_value = select.get("value")
#         if select_name and select_value:
#             data[select_name] = select_value

#     data['Submit'] = "Submit"
#     # inputs = form_details["select"]
#     print(data)
#     if form_details["method"] == "post":
#         return session.post(target_url, data=data)
#         # print(rs.request.url)

#     elif form_details["method"] == "get":
#         # GET request
#         rs = session.get(target_url, params=data)
#         print(rs.url)
#         return rs
#     else:
#         print("NO METHOD")

# def scan_xss(url):
#     """
#     Given a `url`, it prints all XSS vulnerable forms and
#     returns True if any is vulnerable, False otherwise
#     """
#     # get all the forms from the URL
#     forms = get_all_forms(url)
#     print(f"[+] Detected {len(forms)} forms on {url}.")
#     payload = """<script>document.write('<p>TWES</p>')</script>"""
#     is_vulnerable = False
#     # iterate over all forms
#     for form in forms:
#         form_details = get_form_details(form)
#         # pprint(form_details)
#         # pprint(content)
#         with open("XSSpayloads") as XSSpayloads:
#             # for payload in XSSpayloads:
#             content = submit_form(form_details, url, payload).content.decode()
#             if payload.lower() in content.lower():
#                 print(f"[+] XSS Detected on {url}")
#                 print(f"[*] Form details:")
#                 pprint(form_details)
#                 is_vulnerable = True
#                 break
#     return is_vulnerable

def scan_xss_dom(url):
    '''
    TODO
    '''
    # payload = "<SCrIpT>window.exploitDetected = true</ScRiPt>"
    # xss_url = url + payload

    # r = session.get(xss_url)
    options = Options()
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")  # linux only
    options.add_argument("--headless")
    # webdriver.firefox.options.headless = True
    # fireFoxOptions.set_headless()
    browser = webdriver.Chrome(options=options)

    print(url)
    browser.get(url)
    browser.add_cookie(
        {"name": "PHPSESSID", "value": "2r5bfcokovgu1hjf1v08amcd1g"})
    browser.get(url)
    exploitDetected = browser.execute_script("return window.exploitDetected")
    browser.quit()
    return exploitDetected


if __name__ == "__main__":
    url = "http://dvwa-win10/vulnerabilities/xss_r/"
    # url = "https://xss-game.appspot.com/level1/frame"
    url = "http://www.insecurelabs.org/Task/Rule1"

    forms = HTMLParser.get_all_forms(url, session)
    is_vulnerable = False
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        with open("XSSpayloads") as XSSpayloads:
            for payload in XSSpayloads:
                response, data = HTMLParser.submit_form(
                    form_details, url, payload, session)
                if payload.lower() in response.content.decode().lower():
                    print(f"[+] XSS Detected on {url}")
                    print(f"[*] Form details:")
                    pprint(form_details)
                    is_vulnerable = True
                    break
    dom_payload = "<SCrIpT>window.exploitDetected=true</ScRiPt>"
    for form in forms:
        form_details = HTMLParser.get_form_details(form)
        response, data = HTMLParser.submit_form(
            form_details, url, dom_payload, session)
        s = unquote_plus(response.url)
        if scan_xss_dom(s):
            print("DOM")
            is_vulnerable = True
    print(is_vulnerable)
    # r = session.get(url)
    # pprint(r.url)
    # print(scan_xss(url))
