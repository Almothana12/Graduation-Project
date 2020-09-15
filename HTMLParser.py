from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, unquote_plus
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
    if form.attrs.get("action"):
        action = form.attrs.get("action").lower()
    else:
        action = form.attrs.get("action")
    # get the form method
    method = form.attrs.get("method", "get").lower()
    # get the form name
    name = form.attrs.get("name")
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    selects = []
    for select_tag in form.find_all("select"):
        select_type = select_tag.attrs.get("type")
        select_name = select_tag.attrs.get("name")
        select_value = select_tag.attrs.get("value", "")
        selects.append({"type": select_type, "name": select_name, "value": select_value})
    
    textareas = []
    for textarea_tag in form.find_all("textarea"):
        textarea_name = textarea_tag.attrs.get("name")
        textarea_value = textarea_tag.attrs.get("value")
        textareas.append({"name": textarea_name, "value": textarea_value})

    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    details["selects"] = selects
    details["textareas"] = textareas

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
    for input in form_details["inputs"]:
        # replace all text and search values with `value` 
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = payload 
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            
            data[input_name] = input_value

    for select in form_details["selects"]:
        select["value"] = payload
        select_name = select.get("name")
        select_value = select.get("value")
        if select_name and select_value:
            data[select_name] = select_value
    # print(form_details["selects"])

    for textarea in form_details["textareas"]:
        textarea["value"] = payload
        textarea_name = textarea.get("name")
        textarea_value = textarea.get("value")
        if textarea_name and textarea_value:
            data[textarea_name] = textarea_value


##############################################
    # for select_tag in form_details["selects"]:
    #     if select_tag["type"] == "text":
    #         select_tag["value"] = payload
    #     data[select_tag["name"]] = payload
    # for input_tag in form_details["inputs"]:
    #     if input_tag["value"] or input_tag["type"] == "hidden":
    #                 # any input form that has some value or hidden,
    #                 # just use it in the form body
    #         try:
    #             data[input_tag["name"]] = input_tag["value"] + payload
    #         except:
    #             pass
    #     elif input_tag["type"] != "submit":
    #         # all others except submit, use some junk data with special character
    #         data[input_tag["name"]] = f"1{payload}"
    # TODO: return only the data, leave the actual form submittion to the caller
    # print(unquote_plus(target_url + "?" + urlencode(data)))
    # print(target_url)
    if form_details["method"] == "post":
        response = session.post(target_url, data=data)
        # print(rs.request.url)

    elif form_details["method"] == "get":
        # GET request
        # response = session.get(unquote_plus(target_url + "?" + urlencode(data)))
        response = session.get(target_url, params=data)
        # print(response.url)
    else:
        print("NO METHOD")
    return response