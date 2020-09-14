from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode
import requests

def get_all_forms(url, session):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = BeautifulSoup(session.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    
    # print(form)
    # get the form action
    action = form.attrs.get("action")#.lower()
    # get the form method
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    selects = []
    for select_tag in form.find_all("select"):
        select_type = select_tag.attrs.get("type", "text")
        select_name = select_tag.attrs.get("name")
        select_value = select_tag.attrs.get("value", "")
        selects.append({"type": select_type, "name": select_name, "value": select_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    details["selects"] = selects

    return details

def submit_form(form_details, url, payload, session):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the URL for the form
        value (str): the value to be submitted to the form
        session (requests.Session): a session object for submitting the form
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # target_url = url
    data = {} # the data to be submitted

    # get the inputs from the form
    # for input in form_details["inputs"]:
    #     # replace all text and search values with `value` 
    #     if input["type"] == "text" or input["type"] == "search":
    #         input["value"] = value
                
    #     input_name = input.get("name")
    #     input_value = input.get("value")
    #     if input_name and input_value:
    #         # if input name and value are not None, 
    #         # then add them to the data of form submission
            
    #         data[input_name] = input_value

    # for select in form_details["selects"]:
    #     if select["type"] == "text":
    #         select["value"] = value
    #     select_name = select.get("name")
    #     select_value = select.get("value")
    #     if select_name and select_value:
    #         data[select_name] = select_value
    # print(form_details["selects"])
    for select_tag in form_details["selects"]:
        if select_tag["type"] == "text":
            select_tag["value"] = payload
        data[select_tag["name"]] = "English" + payload
    for input_tag in form_details["inputs"]:
        if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
            try:
                data[input_tag["name"]] = input_tag["value"] + payload
            except:
                pass
        elif input_tag["type"] != "submit":
            # all others except submit, use some junk data with special character
            data[input_tag["name"]] = f"test{payload}"
    # TODO: return only the data, leave the actual form submittion to the caller
    # print(urlencode(data))
    if form_details["method"] == "post":
        response = session.post(target_url, data=data)
        # print(rs.request.url)

    elif form_details["method"] == "get":
        # GET request
        response = session.get(target_url, params=data)
        # print(rs.url)
    else:
        print("NO METHOD")
    return response, data