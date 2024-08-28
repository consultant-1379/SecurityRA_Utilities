"""
 This script contains core functionality to execute REST calls
"""

import logging
import re
import requests.packages.urllib3

from MTELoopScripts.etc.pylibs.request_retry import request_retry
import MTELoopScripts.etc.pylibs.configuration as configuration

requests.packages.urllib3.disable_warnings()

CONFIG = configuration.UtilsConfig()

logging.getLogger("requests").setLevel(logging.WARNING)


def get(url):
    """
    Function to perform GET requests's to EMT
    :param url: URL you want to run your GET request against
    :return: GET request response
    """
    logging.info("Sending GET REST request - %s", str(url))
    if any(['fem110' in str(url), 'fem114' in str(url), 'fem168' in str(url),
            'fem169' in str(url)]):
        fem = re.split('//|-', url)[1]
        auth_username = CONFIG.get("COMMON_VARIABLES",
                                   "thunderbee_functional_user")
        api_token = CONFIG.get("COMMON_VARIABLES",
                               "thunderbee_functional_user_api_token_of_{0}".
                               format(fem))
        response = request_retry("GET", url, 5, None, (auth_username, api_token))
    else:
        response = request_retry("GET", url, 5)
    logging.debug("GET request response: \n %s", response)
    return response.json()


def put(url, body):
    """
    Function to perform PUT requests's to EMT
    :param url: URL you want to run your PUT request against
    :param body: The body you want to send in your PUT request
    :return: PUT request response
    """
    logging.info("Sending PUT REST request - %s", str(url))
    logging.info("PUT Body: %s", str(body))
    response = request_retry("PUT", url, 5, body)
    logging.debug("PUT request response: \n %s", response.text)
    return response


def post(url, body):
    """
    Function to perform POST requests to EMT
    :param url: URL you want to run your POST request against
    :param body: The body you want to send in your POST request
    :return: POST request response
    """
    logging.info("Sending POST REST request - %s", str(url))
    logging.debug("POST Body: %s", str(body))
    response = request_retry("POST", url, 5, body)
    logging.debug("POST request response: \n %s", response.text)
    return response


def delete(url):
    """
    Function to perform DELETE requests to EMT
    :param url: URL you want to run your DELETE request against
    :return: DELETE request response
    """
    logging.info("Sending DELETE REST request - %s", str(url))
    response = request_retry("DELETE", url, 5)
    logging.debug("DELETE request response: \n %s", response.text)
    return response