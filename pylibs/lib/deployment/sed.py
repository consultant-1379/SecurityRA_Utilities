"""Module to represent the SED for a cloud deployment"""
import logging
import sys

from MTELoopScripts.etc.pylibs.lib.cifwk.dit import DIT


class SED(object):
    """This is an object to represent a SED within a cloud deployment """

    def __init__(self, sed_id):
        self.sed_id = sed_id
        self._sed_parameters = self._retrieve_parameters_from_sed()

    @property
    def httpd_fqdn(self):
        """Retrieves the httpd fqdn from the sed
        :return: httpd_fqdn
        """
        return self._retrieve_value_from_sed("httpd_fqdn")

    def _retrieve_value_from_sed(self, sed_key):
        """Queries the sed to get the value for the key passed in
        :param sed_key: The sed parameter key name
        :return: the value of the sed parameter
        """
        try:
            return self._sed_parameters[sed_key]
        except KeyError as error:
            logging.error(error.__class__.__name__ +
                          " Unable to find " + sed_key)
            sys.exit(1)

    def _retrieve_parameters_from_sed(self):
        """ We will go to the DIT to get the sed for a given sed id
        :return: sed parameters
        """
        sed_content = DIT().get_document_content(self.sed_id, "content")
        try:
            return sed_content["parameter_defaults"]
        except KeyError:
            try:
                return sed_content["parameters"]
            except KeyError as error:
                logging.error("Unable to find sed content")
                logging.error(error.__class__.__name__)
                sys.exit(1)