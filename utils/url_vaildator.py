import logging
import requests

log = logging.getLogger(__name__)

def valid_url(url, session):
    """Check if `url` is valid and reachable

    Args:
        url (str): The url to check

    Returns:
        bool: True if `url` is valid and reachable
    """
    # TODO return error codes?
    try:
        response = session.get(url)
        if response.history:
            log.warning(f"Redirected to {response.url}")
        # raise an HTTPError if the request is unsuccessful
        response.raise_for_status() 
    except requests.ConnectionError as err:
        log.debug(err)
        log.error(f"Could Not Reach URL: {err.request.url}")
        return False
    except requests.HTTPError as err:
        log.debug(err)
        log.error(f"URL Returned {err.response.status_code}")
        return False
    except requests.Timeout as err:
        log.debug(err)
        log.error("Request Timed Out")
        return False
    return True