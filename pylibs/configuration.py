""" This python file used to access the utils.ini constants
"""

import logging

from ConfigParser import SafeConfigParser
from os.path import expanduser, join, dirname


def convert_to_comma_string(profiles):
    """
    Converts a list to comma separated string
    """
    return ",".join(profiles)


class _GeneralConfig(SafeConfigParser):
    """Private class to remove boilerplate ini read operation"""

    def __init__(self, file_path, file_name):
        SafeConfigParser.__init__(self)
        self.read([join(file_path, file_name),
                   expanduser('~/{0}'.format(file_name))])


class UtilsConfig(SafeConfigParser):
    """
    Reads in from the utils.ini file in pylibs

    This class extends the SafeConfigParser
    and reads in the utils.ini file.
    """

    def __init__(self):
        SafeConfigParser.__init__(self)
        self.read([
            join(dirname(__file__), 'utils.ini'),
            expanduser('~/.utils.ini')
        ])


class FTPConfigReader(_GeneralConfig):
    """
    Reads in from the ftp_server.ini file that
    contains predefined profile templates.
    """

    CLOUD_SECTION = "CLOUD_MAPPING"

    def __init__(self):
        _GeneralConfig.__init__(self, dirname(__file__), "ftp_server.ini")

    def get_cloud_mapping(self, key):
        """
        Get the cloud mapping section of the ftp configuration file
        :return: value for key
        :raises ConfigParser.NoOptionError if key is not in configuration
        """
        logging.debug("Looking up the {0} section using key {1}".format(
            self.CLOUD_SECTION, key))
        value = self.get(self.CLOUD_SECTION, key)
        logging.debug("retieved the following value {0}".format(value))
        return value

    @property
    def deployment_key(self):
        """The lookup key in the ini file"""
        return self.get_cloud_mapping("deployment_key_name")

    @property
    def dmt_key(self):
        """The lookup key in the ini file"""
        return self.get_cloud_mapping("dmt_key_name")

    @property
    def deployment_mappings_url(self):
        """The lookup key in the ini file"""
        url = self.get_cloud_mapping("ftp_maintrack_properties_url") +\
            self.get_cloud_mapping("deployment_mappings")
        return url