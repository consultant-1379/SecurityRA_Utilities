"""
 This script contains an interface towards an EMT deployment module
 """

import logging
import json
import urllib2

from MTELoopScripts.etc.pylibs.lib.emt import emt_core
from MTELoopScripts.etc.pylibs.lib.emt.deployments.deployment \
    import EMTDeployment
from MTELoopScripts.etc.pylibs.lib.utils.url import UrlBuilder
from MTELoopScripts.etc.pylibs import configuration

CONFIG = configuration.UtilsConfig()


class DeploymentIdNotFound(Exception):
    """
    Exception for instances where we cannot retrieve a deployment id
    """
    pass


class EMTDeploymentsModule(object):
    """This class provides an interface towards the EMT Deployments module."""
    ID_FIELD = "_id"
    DEPLOYMENTS_PATH = "/api/deployments/"
    SEARCH_PATH = "search"

    def __init__(self):
        self._emt_url = CONFIG.get("MT_Cloud", "emt_url")

    @property
    def deployments(self):
        """Retrieve all deployments currently in EMT"""
        logging.info("Retrieves all the deployments in EMT")

        url_builder = UrlBuilder(self._emt_url).\
            append_path(self.DEPLOYMENTS_PATH)

        response = emt_core.get(url_builder.url)
        return self._convert_to_deployments(response)

    def retrieve_by_name(self, deployment_name):
        """
        Get a specific deployments id
        :param deployment_name: name of the deployment you want the id of
        :return: deployment id
        """
        logging.debug("Getting %s 's _id.", str(deployment_name))

        query_string = "name=" + str(deployment_name)
        response = self.query(query_string)
        if not response:
            raise DeploymentIdNotFound()
        return response[0].id

    def property_setter(self, deployment, key_to_set, value_to_set, username):
        """
        Update a property for the given deployment
        :param deployment: The deployment
        :param key_to_set: key of property to set on deployment
        :param value_to_set: value of property to set on deployment
        :param username: username of who is setting property
        :return: a PUT response for logging purposes
        """
        url_builder = UrlBuilder(self._emt_url). \
            append_path(self.DEPLOYMENTS_PATH).append_path(deployment.id)
        request_body =\
            '{"username": "' + username + '","deployment": ' \
            '{"' + str(key_to_set) + '": "' + value_to_set + '"}}'

        request_body = json.loads(request_body)
        return emt_core.put(url_builder.url, request_body)

    def query(self, query):
        """
        Executes a query against the deployments module
        :param query: a query to execute against EMT
        :return: a response from deployments module in deployment object format
        """
        logging.info("Executing the following query - %s", query)
        url_builder = UrlBuilder(self._emt_url) \
            .append_path(self.DEPLOYMENTS_PATH) \
            .append_path(self.SEARCH_PATH) \
            .add_param("q=" + query)
        response = emt_core.get(url_builder.url)
        logging.debug("Get deployment id response: %s", response)

        return self._convert_to_deployments(response)

    @staticmethod
    def _convert_to_deployments(emt_json):
        """
        Converts a json response to a deployment object
        :param emt_json: json response from an EMT call
        :return: list of emt deployment objects
        """
        emt_list = []
        for dep in emt_json:
            emt_list.append(EMTDeployment(dep))
        return emt_list