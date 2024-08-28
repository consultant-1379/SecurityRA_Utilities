""" Module representing functionality towards the Deployment Inventory Tool """
import sys
import logging

from MTELoopScripts.etc.pylibs import configuration
from MTELoopScripts.etc.pylibs.lib.utils.url import UrlBuilder

CONFIG = configuration.UtilsConfig()


class DIT(object):

    """Provides an interface towards the Deployment Inventory Tool"""
    deployments_path = "/api/deployments/"
    projects_path = "/api/projects/"
    documents_path = "/api/documents/"
    labels_path = "/api/labels/"
    pods_path = "/api/pods/"

    def __init__(self):
        self.dit_url = CONFIG.get("MT_Cloud", "dit_url")

    @property
    def deployments(self):
        """ Get all of the deployments in DIT
        :return: deployments json array
        """
        return self._query_collection(self.deployments_path)

    @property
    def projects(self):
        """Returns all Projects in DIT
        :return: projects json array
        """
        return self._query_collection(self.projects_path)

    @property
    def pods(self):
        """Returns all POD content in DIT
        :return: pods json array
        """
        return self._query_collection(self.pods_path)

    @property
    def documents(self):
        """Get all documents in DIT
        :return: documents json array
        """
        return self._query_collection(self.documents_path)

    @property
    def labels(self):
        """Get all labels in DIT
        :return: labels json array
        """
        return self._query_collection(self.labels_path)

    def get_deployment_content(self, deployment_id, key):
        """Get deployment specific content from the DIT deployment document
        :param deployment_id: The DIT id for this deployment
        :param key: filter on this key
        :return: content value
        """
        query = "fields=" + key
        url_builder = UrlBuilder(self.dit_url).\
            append_path(self.deployments_path).\
            append_path(str(deployment_id) + "/").\
            add_param(query)
        return self._query_json(url_builder, key)

    def get_project_content(self, project_id, key):
        """Get openstack project specific content from the DIT project document
        :param project_id: The project to filter on
        :param key: Key to search for in project contents
        :return: Filtered project content
        """

        query = "fields=" + key
        url_builder = UrlBuilder(self.dit_url).append_path(
            self.projects_path).append_path(str(project_id) + "/").\
            add_param(query)
        return self._query_json(url_builder, key)

    def get_pod_content(self, pod_id, key):
        """Get Openstack pod specific content from the DIT pod document
        :param pod_id: The pod to filter on
        :param key: The key to search for in pod contents
        :return: Filtered POD content
        """

        query = "fields=" + key
        url_builder = UrlBuilder(self.dit_url).append_path(self.pods_path).\
            append_path(str(pod_id) + "/").add_param(query)
        return self._query_json(url_builder, key)

    def get_document_content(self, document_id, key):
        """Get document specific content from the DIT document
        :param document_id: The document to filter on
        :param key: The key to search for in document contents
        :return: Filtered document content
        """

        query = "fields=" + key
        url_builder = UrlBuilder(self.dit_url).append_path(
            self.documents_path).append_path(str(document_id) + "/").\
            add_param(query)
        return self._query_json(url_builder, key)

    def _query_collection(self, path):
        """Query the high level DIT paths, which are exposed as properties
        :param path: which high level path to query.
        :return: The DIT json response
        """

        url_builder = UrlBuilder(self.dit_url).append_path(path)
        return self._query_dit(url_builder)

    def _query_json(self, url_builder, key):
        """Query the json response for a given value"""
        dit_json = self._query_dit(url_builder)

        try:
            return dit_json[key]
        except KeyError as error:
            logging.error(error.__class__.__name__ + "Unable to find " + key)
            sys.exit(1)

    @staticmethod
    def _query_dit(url_builder):
        """ Execute the query on the urlbuilder
        :param url_builder: url to query
        :return: returned json object from the request
        """
        logging.info("Getting : " + url_builder.url)
        dit_json = UrlBuilder.response_to_json(
            url_builder.return_url_response())
        logging.debug("Response json" + str(dit_json))
        return dit_json

    def get_deployment_id_from_name(self, deployment_name):
        """ Get deployment_id for a given deployment
        :param deployment_name:
        :return: DIT deployment ID field for the deployment
        """
        key = "_id"
        deployment_query = "q=name=" + str(deployment_name)
        query = "fields=" + key
        url_builder = UrlBuilder(self.dit_url).append_path(
            self.deployments_path).add_param(deployment_query).add_param(query)

        dit_json = self._query_dit(url_builder)
        try:
            return dit_json[0][key]
        except IndexError as error:
            logging.error(error.__class__.__name__ +
                          "Call did not return a deployment")
            logging.error(dit_json)
            sys.exit(1)
        except KeyError as error:
            logging.error(error.__class__.__name__ + "Unable to find " + key)
            logging.error(dit_json)
            sys.exit(1)