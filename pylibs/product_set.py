"""
This module is used to query CIFWK Portal
and retrieve certain product set information
"""

import json
import logging
import sys

import common_functions
import configuration

CONFIG = configuration.UtilsConfig()


class ProductSet(object):
    """
    This class queries the CI portal using
    CIFWK REST Interfaces/API to obtain product set information.

    """

    ENM_ISO_ARTIFACT = CONFIG.get("COMMON_VARIABLES", "enm_iso")
    VNFLCM_ARTIFACT = CONFIG.get("COMMON_VARIABLES", "vnflcm")
    CIFWK_URL = CONFIG.get("COMMON_VARIABLES", "cifwk_url")

    ENM_ISO_CXP = ENM_ISO_ARTIFACT.split("_")[-1]
    VNFLCM_CXP = VNFLCM_ARTIFACT.split("_")[-1]

    def __init__(self, product_set_version):
        self.product_set_version = product_set_version

        self.product_set_json = self.__product_set_content

        self.enm_version = \
            self.obtain_product_set_content([self.ENM_ISO_CXP],
                                            "version").get(self.ENM_ISO_CXP)
        self.vnflcm_version = \
            self.obtain_product_set_content([self.VNFLCM_CXP],
                                            "version").get(self.VNFLCM_CXP)

    @property
    def __product_set_content(self):
        """
        Using CIFWK URL to obtain Product Set content in JSON

        :return product_set_content:
        """
        # TO DO Use URLBuilder here when delivered.
        product_set_rest_call = \
            self.CIFWK_URL + \
            "/getProductSetVersionContents/?productSet=ENM&version=" + \
            self.product_set_version
        url_response = common_functions.return_url_response(
            product_set_rest_call)
        product_set_content = common_functions.return_json_object(url_response)
        return product_set_content

    def get_artifact_content(self, artifact_name, artifact_version):
        """
        Using CIFWK URL to obtain artifact content in JSON

        :param artifact_name:
        :param artifact_version:
        :return artifact_content:
        """
        # TO DO Use URLBuilder here when delivered.
        product_set_rest_call = \
            self.CIFWK_URL + \
            "/getPackagesInISO/?isoName=" + \
            artifact_name + \
            "&isoVersion=" + \
            artifact_version + \
            "&useLocalNexus=true"
        url_response = common_functions.return_url_response(
            product_set_rest_call)
        artifact_content = common_functions.return_json_object(url_response)
        return artifact_content

    def obtain_product_set_content(self, product_names, content):
        """
        Obtain Product Set content

        :param content:
        :param product_names:
        :return product_names_content:
        """
        try:
            product_names_content = \
                self.parse_json_for_specific_content(product_names, content)
        except AttributeError:
            logging.error("Unexpected JSON, therefore exiting...")
            sys.exit(1)
        if not product_names_content:
            logging.error("No " + content + " retrieved for " +
                          str(product_names))
            sys.exit(1)
        return product_names_content

    def parse_json_for_specific_content(self, product_names, content):
        """
        Parse JSON for particular Product Set content

        :param content:
        :param product_names:
        :return product_names_content:
        """
        product_names_content = {}
        product_set_products = self.product_set_json[0]["contents"]
        for product in product_set_products:
            if product.get("artifactNumber") in product_names:
                product_names_content[product.get("artifactNumber")] = \
                    product.get(content)
        return product_names_content

    def obtain_artifact_content_nexus_urls(self, artifact_json,
                                           artifact_names):
        """
        Parse JSON for particular artifact content nexus urls

        :param artifact_json:
        :param artifact_names:
        :return artifact_names_nexus_urls:
        """
        try:
            artifact_names_nexus_urls = \
                self.parse_json_for_artifact_nexus_urls(artifact_json,
                                                        artifact_names)
        except AttributeError:
            logging.error("Unexpected JSON, therefore exiting...")
            sys.exit(1)
        if not artifact_names_nexus_urls:
            logging.error("No Nexus URLs retrieved for " + str(artifact_names))
            sys.exit(1)
        return artifact_names_nexus_urls

    def parse_json_for_artifact_nexus_urls(self, artifact_json,
                                           artifact_names):
        """
        Parse JSON for particular artifact content nexus urls

        :param artifact_json:
        :param artifact_names:
        :return artifact_names_nexus_urls:
        """
        artifact_names_nexus_urls = {}
        iso_packages = artifact_json["PackagesInISO"]
        for package in iso_packages:
            if package['number'] in artifact_names:
                artifact_names_nexus_urls[package['number']] = package['url']
        return artifact_names_nexus_urls

    def create_json_for_nwci(self, artifacts):
        """
        Create JSON necessary for NWCI deploy

        :param artifacts:
        :return artifacts_json:
        """
        artifacts_json = {}
        artifacts_json.update({"cloud_templates_details": {},
                               "deployment_workflows_details": {},
                               "media_details": {}})

        for artifact, url in artifacts.items():
            if artifact == "CXP9033953" or artifact == "CXP9033639":
                artifacts_json["cloud_templates_details"].update(
                    {artifact: url})
            elif artifact == "CXP9034151":
                artifacts_json["deployment_workflows_details"].update(
                    {artifact: url})
            else:
                artifacts_json["media_details"].update({artifact: url})
        artifacts_json = json.dumps(artifacts_json)
        return artifacts_json

    def get_enm_iso(self, drop):
        """
        Using CIFWK URL to obtain ENM ISO version

        :param drop:
        :return ENM ISO Version:
        """
        product_set_rest_call = self.CIFWK_URL + \
            "/api/deployment/info/ENM" \
            "/productset/" + drop + "/" \
            + self.product_set_version
        url_response = common_functions.return_url_response(
            product_set_rest_call)
        product_set_content = common_functions.return_json_object(url_response)
        return product_set_content['ENMIsoInfo']['isoVersion']

    def get_artifact_version(self, product_set_artifact_version):
        """
        Using CIFWK URL to obtain artifact version

        :param product_set_artifact_version:
        :return product set contents version:
        """
        product_set_rest_call = self.CIFWK_URL + \
            "/api/productSet/ENM/AOM901151/" + self.product_set_version + "/" \
            + "?format=json"
        url_response = common_functions.return_url_response(
            product_set_rest_call)
        product_set_artifacts = common_functions.return_json_object(url_response)
        for product_set_artifact in product_set_artifacts:
            if product_set_artifact['artifact'] == product_set_artifact_version:
                return product_set_artifact['version']