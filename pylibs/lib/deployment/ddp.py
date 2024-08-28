""" Module representing DDP information for a given deployment """
import sys
import logging

from MTELoopScripts.etc.pylibs.lib.cifwk.dit import DIT


class DDP(object):
    """
    This represents the DDP information from DIT DDP document
    of a deployment
    """

    _dit = DIT()
    _content = None
    _document_id = None

    def __init__(self, document_id):
        self._document_id = document_id
        self._content = self._dit.get_document_content(self._document_id,
                                                       "content")

    @property
    def port(self):
        """
        The DDP port number associated with a deployment
        :return: port
        """
        return self._retrieve_value_from_content("port")

    @property
    def cron(self):
        """
        The DDP cron associated with a deployment
        :return: cron
        """
        return self._retrieve_value_from_content("cron")

    @property
    def hostname(self):
        """
        The DDP hostname associated with a deployment
        :return: hostname
        """
        return self._retrieve_value_from_content("hostname")

    def _retrieve_value_from_content(self, key_to_search):
        """
        Queries the content to get the value for the key passed in
        :param key_to_search: a key in the DDP json object
        :return: the value for key
        """
        try:
            return self._content[key_to_search]
        except KeyError as error:
            logging.error(error.__class__.__name__ + " Unable to find " +
                          key_to_search)
            sys.exit(1)