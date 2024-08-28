"""
This module is used for querying the ENM ISO
"""
import common_functions
import configuration

CONFIG = configuration.UtilsConfig()


class ENMISO(object):
    """
    This is a class which will represent the ISO
    """

    ENM_ISO_ARTIFACT = CONFIG.get("COMMON_VARIABLES", "enm_iso")
    CIFWK_URL = CONFIG.get("COMMON_VARIABLES", "cifwk_url")

    def __init__(self, version):
        self.version = version
        self.content = self.get_iso_contents()

    def get_iso_contents(self):
        """
        Will return the contents of an ENM ISO
        :return ENM ISO content:
        """
        # TO DO Use URLBuilder here when delivered.
        iso_content_rest_call = \
            self.CIFWK_URL + \
            "/getPackagesInISO/?isoName=" + \
            self.ENM_ISO_ARTIFACT + \
            "&isoVersion=" + \
            self.version + \
            "&useLocalNexus=true"
        url_response = \
            common_functions.return_url_response(
                iso_content_rest_call)
        artifact_content = \
            common_functions.return_json_object(
                url_response)
        return artifact_content

    def parse_iso_content_for_field(self, package_name, field_to_find):
        """
        This function parses through the ISO contents for a specified field
        :param package_name: The name of package to get info from
        :param field_to_find: The field to return from the package
        :return: value of the field
        """
        for content_type in self.content["PackagesInISO"]:
            if content_type["name"] == package_name:
                return content_type[field_to_find]