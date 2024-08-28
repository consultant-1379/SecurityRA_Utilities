"""
This script allows a user to attempt to make a request multiple times if the target host is
temporarily down
"""

import logging
import sys
import time
import requests

import configuration

# pylint: disable=E1101
CONFIG = configuration.UtilsConfig()


def request_retry(type_of_request, url, max_retry, body=None, auth_value=None):
    """
    Function to retry requests if the target host is not found. Geometric retry is used here.
    :param type_of_request: Which REST request is being conducted
    :param url: URL you want to run your request against
    :param max_retry: Amount of times to retry the request
    :param body: The payload which will be sent in the request body
    :param auth_value: Authentication values for the specified request
    :return: Request response
    """
    count = 0
    response = None
    valid_response_codes = [requests.codes.ok, requests.codes.created]
    logging.debug('type_of_request: {0}'.format(str(type_of_request)))
    logging.debug('url: {0}'.format(str(url)))
    proxy_name = CONFIG.get("COMMON_VARIABLES", "proxy_server_hostname")
    proxy = {'http': proxy_name}
    while count < max_retry:
        logging.debug('Trying request')
        try:
            if type_of_request == "GET":
                logging.debug('Doing a GET request')
                response = requests.get(url, verify=False, auth=auth_value, proxies=proxy,
                                        timeout=5)
            elif type_of_request == "PATCH":
                logging.debug('Doing a PATCH request')
                response = requests.patch(url, json=body, timeout=5, proxies=proxy)
            elif type_of_request == "PUT":
                logging.debug('Doing a PUT request')
                response = requests.put(url, json=body, timeout=5, proxies=proxy)
            elif type_of_request == "POST":
                logging.debug('Doing a POST request')
                response = requests.post(url, json=body, timeout=20, proxies=proxy)
            elif type_of_request == "DELETE":
                logging.debug('Doing a DELETE request')
                response = requests.delete(url, timeout=10, proxies=proxy)
            else:
                logging.error('Unsupported type of request {0}'.format(type_of_request))
                sys.exit(1)
            if response is not None:
                if response.status_code in valid_response_codes:
                    break
            raise requests.exceptions.RequestException
        except requests.exceptions.ProxyError as ProxyException:
            if 'http' in proxy:
                logging.warn('Could not make request using HTTP, will attempt HTTPS now')
                proxy = {'https': proxy_name}
            else:
                logging.error('Tried both HTTP and HTTPS but still getting a Proxy error')
                raise ProxyException
        except requests.exceptions.RequestException as RequestException:
            if response is None:
                logging.error('Got no response object back! Failed to make request.')
                raise RequestException
            logging.debug('Response status code: ' + str(response.status_code))
            logging.debug('Response reason: ' + str(response.reason))
            logging.debug('Response output: ' + str(response.text))
            if response.status_code != requests.codes.not_found:
                logging.error('Request failed. Received response code: '
                              + str(response.status_code))
                raise RequestException
            count += 1
            if count == max_retry:
                logging.error("Failed to reach target host to execute request after {0} tries. "
                              "Failing...".format(max_retry))
                raise RequestException
            logging.warn("Failed to reach target host to execute request. "
                         "Sleeping and then trying again...")
            time.sleep(2 ** count)
    return response