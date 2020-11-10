import logging
from urllib.parse import unquote_plus, urlencode, urljoin

import requests
from bs4 import BeautifulSoup
import bs4

log = logging.getLogger(__name__)

def get_all_forms(session: requests.Session, url: str) -> bs4.element.ResultSet:
    """Return all the forms from the given `url`"""
    soup = BeautifulSoup(session.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form: bs4.element.Tag) -> dict:
    """Return a dict containing details about the given `form`"""
    details = {}
    # get the form action
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
        input_value = input_tag.attrs.get("value")
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
    details["name"] = name
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    details["selects"] = selects
    details["textareas"] = textareas
    # TODO add line number of form

    return details


def submit_form(form_details: dict, 
                url: str, 
                payload: str, 
                session: requests.Session) -> requests.models.Response:
    """Fill the given `form` with `payload` and submit it to `url`

    Args:
        form_details (dict): A dictionary with the form's details
        url (str): The URL of the form
        payload (str): the value to be submitted to the form
        session (requests.Session): A Session object

    Returns:
        requests.models.Response: The HTTP response from the web server
    """
    # log.debug(f"submit_form: form_details={form_details} URL={url} payload={payload}")

    # construct the full URL if the url provided in action is relative
    target_url = urljoin(url, form_details["action"])
    payload_injected = False
    data = {} # the data to be submitted
    # get the inputs from the form
    for input in form_details["inputs"]:
        # replace all text and search values with the payload
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = payload
            payload_injected = True
        # if it doesn't have a type
        if not input["type"]:
            input["value"] = payload
            payload_injected = True
        input_name = input["name"] 
        input_value = input["value"]
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    for select in form_details["selects"]:
        # select["value"] = payload
        select_name = select["name"]
        select_value = payload
        payload_injected = True
        if select_name and select_value:
            data[select_name] = select_value
    # print(form_details["selects"])

    for textarea in form_details["textareas"]:
        # textarea["value"] = payload
        textarea_name = textarea["name"]
        textarea_value = payload
        payload_injected = True
        if textarea_name and textarea_value:
            data[textarea_name] = textarea_value

    if not data or not payload_injected:
        log.debug(f"submit_form: No data to submit for form: {form_details} in {url}")
        return ""
    if form_details["method"] == "post":
        # response = session.post(target_url, data=data, timeout=(3.05, 7))
        response = session.post(target_url, data=data)

        # log.debug(f"submit_form: POST: {response.url} Data: {data}")
    elif form_details["method"] == "get":
        response = session.get(target_url, params=data)
        # log.debug(f"submit_form: GET: {response.url}")
    else:
        log.warning("submit_form: Invalid or no form method")
    return response