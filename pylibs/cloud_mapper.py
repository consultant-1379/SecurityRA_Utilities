"""Module used for mapping DMT to cloud functionality"""
import logging
import sys
import common_functions

from configuration import FTPConfigReader


class CloudMappingJSONReader(object):
    """Uses deploymentMappings.json file to map DIT deployment name to
    a DMT Cluster Id"""

    json_file = None
    cloud_config = FTPConfigReader()

    def __init__(self, url):
        """
            :param url: address of the FTP server where JSON file is stored
        """

        response = common_functions.return_url_response(url)
        self.json_file = common_functions.return_json_object(response)
        logging.debug("JSON: " + str(self.json_file))

    @staticmethod
    def validate_dictionary_for_key(dictionary, lookup_key):
        """Validate the key in case the user has entered it incorrectly
        :param dictionary: dictionary to query for key
        :param lookup_key: the key whose corresponding value we expect to exist
        :return: value from the dictionary
        """
        try:
            value = dictionary[lookup_key]
        except KeyError:
            logging.error("JSON does not contain expected lookup key %s",
                          lookup_key)
            sys.exit(1)
        return value

    def get_dmt_id_for_cloud_deployment(self, deployment_name):
        """ This parses the json for a given deployment name to return
        the corresponding DMT id
        :param deployment_name: DIT deployment name
        :return: DMT cluster id
        """

        for deployment_info in self.json_file:
            json_dep_name = self.validate_dictionary_for_key(
                deployment_info, self.cloud_config.deployment_key)
            if deployment_name == json_dep_name:
                json_dmt_id = self.validate_dictionary_for_key(
                    deployment_info, self.cloud_config.dmt_key)
                logging.debug("JSON : dmt_id : {0}, deployment_name : {1}".
                              format(json_dmt_id, deployment_name))
                return json_dmt_id

        logging.warning("{0} does not match any known maintrack deployments".
                        format(deployment_name))
        sys.exit(1)