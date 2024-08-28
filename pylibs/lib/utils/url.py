"""Url Module for url related operations"""
import logging
import json
import socket
import urllib2
import sys

from MTELoopScripts.etc.pylibs import configuration

CONFIG = configuration.UtilsConfig()


class UrlBuilder(object):
    """
    This class enables building a url from its component parts.

    The following describes what are the component parts of a Url.
    domain: A domain name is a unique reference that identifies
        a server on the internet eg google.com
    sub-domain: A subdomain is a sub-division of the main domain name.
        eg. maps.google.com
    protocol: The protocol declares how your web browser should communicate
        with a web server http://google.com
    Port: The specific port of the server to target
    Path: The path typically refers to a file or directory
    Query: Allows server side querying, denoted by "?=" followed by one or
        more parameters separated by "&"
    Param: Part of a query, is a key pair value "q=url"
    """

    domain = None
    path = None
    params = None
    PARAM_SEPARATOR = "&"  # separator used between parameter values
    QUERY_START = "?"  # used to mark beginning of a query component
    TIMEOUT = 60.0  # timeout in seconds for response requests
    PROXY = CONFIG.get("COMMON_VARIABLES", "proxy_server_hostname")

    def __init__(self, domain):
        self.domain = domain

    def __str__(self):
        return self.url

    @property
    def url(self):
        """
        Get the complete url
        :return: url
        """
        url = self.domain
        if self.path:
            url += self.path
        if self.params:
            url += self.QUERY_START + self.params
        return url

    def append_path(self, sub_path):
        """
        Append the sub-path to path component of the url
        :param sub_path: The sub_path to be appended to the path component
        :return: this object to allow fluent api
        """
        if self.path is None:
            self.path = sub_path
        else:
            self.path += sub_path
        return self

    def add_param(self, param):
        """
        Add a key pair value to list of query parameter.
        :param param: The param to include in the query
        :return: this object to allow fluent api
        """
        if self.params is None:
            self.params = param
        else:
            self.params += self.PARAM_SEPARATOR + param
        return self

    def return_url_response(self):
        """
        Get the response for the UrlBuilder or provided url.
        :return HTML response: Output of the URL
        """
        _url = self.url
        fail_flag = False
        protocols = ['https', 'http']
        logging.debug("Returning URL response from the URL: " + str(_url))

        for protocol in sorted(protocols, reverse=True):
            try:
                logging.debug("Attempting to use proxy {0} over {1}".
                              format(self.PROXY, protocol))
                proxy_handler = urllib2.ProxyHandler({protocol: self.PROXY})
                opener = urllib2.build_opener(proxy_handler)
                urllib2.install_opener(opener)
                url_info = urllib2.urlopen(_url, timeout=self.TIMEOUT)
            except urllib2.HTTPError as error:
                logging.warning("HTTP Error Code: " + str(error.code))
                fail_flag = True
                continue
            except urllib2.URLError as error:
                logging.warning("URL Error: " + str(error))
                logging.warning("URL : Could be proxy or server response "
                                "timed out after {0}s".format(self.TIMEOUT))
                fail_flag = True
                continue
            except ValueError as error:
                logging.warning(
                    "Invalid URL detected. Please pass in a valid URL")
                logging.warning(error)
                fail_flag = True
                continue
            except socket.error as error:
                logging.warning("Socket timeout error")
                logging.warning(error)
                fail_flag = True
                continue
            fail_flag = False
            break

        if fail_flag:
            sys.exit(1)
        else:
            return url_info.read()

    @staticmethod
    def response_to_json(html_response):
        """
        Helper function to convert the url to a json object
        :param html_response:
        :return parsed_json: a json object from the HTML Response
        """
        logging.debug("Returning JSON from HTML response...")
        try:
            parsed_json = json.loads(html_response)
        except ValueError:
            logging.error("Invalid JSON Object")
            logging.error("HTML Response: ")
            logging.error(str(html_response))
            return None
        return parsed_json