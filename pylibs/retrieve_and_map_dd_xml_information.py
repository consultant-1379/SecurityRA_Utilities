"""
This module provides a way to interface with with DMT's DD XML information.
"""

import logging
import sys
import json
import requests
import argparse
import common_functions
import configuration

requests.packages.urllib3.disable_warnings()

CONFIG = configuration.UtilsConfig()

DMT_URL = CONFIG.get("COMMON_VARIABLES", "cifwk_url")
DMT_DD_INFO_URL = DMT_URL + "/api/deployment/deploymentDescription/"
JSON_MAPPING_URL = "https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/content/repositories/" \
                   "releases/com/ericsson/oss/itpf/deployment/descriptions/" \
                   "ERICenmdeploymenttemplates_CXP9031758/1.79.2/" \
                   "ERICenmdeploymenttemplates_CXP9031758-1.79.2.json"


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    ------------
    This script will get necessary deployment description information for the necessary cluster_id

    Examples:
    ------------
    ''' + sys.argv[0] + ''' --cluster_id 435 --get_dd_file_name_from_dmt --output_to_screen
    ''' + sys.argv[0] + ''' --cluster_id 435 --is_xml_format_new --output_to_screen
    ''' + sys.argv[0] + ''' --cluster_id 435 --invert_dd_xml_format dd.xml --output_to_screen
    ''',
        epilog=''''''
    )
    parser.add_argument("-c", "--cluster_id",
                        help="Cluster ID of the deployment to check", required=True)
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity", action="store_true")
    parser.add_argument("-o", "--output_to_screen",
                        help="Option to output the value to screen", nargs='?',
                        const=True)
    parser.add_argument("-g", "--get_dd_file_name_from_dmt",
                        help="This will query DMT and return the name of the required cluster"
                             "ids DD XML file", action="store_true")
    parser.add_argument("-n", "--is_xml_format_new",
                        help="This will query DMT for the required clusters DD XML file. Using "
                             "this, it will then query the json mapping endpoint to "
                             "see if it is an old or new format", action="store_true")
    parser.add_argument("-i", "--invert_dd_xml_format",
                        help="This will query DMT for the required clusters DD XML file. "
                             "Using this, it will then query the json mapping endpoint "
                             "and return the mapped XML to this")
    parser.add_argument("-b", "--get_xml_file_from_dmt",
                        help="This will get the file name prepended with the directory "
                             "the file is located at from DMTs endpoint", action="store_true")
    parser.add_argument("-t", "--get_new_dir_and_file_from_dmt",
                        help="This will get the directory and file name for DD XML files in a "
                             "new format")

    return parser.parse_args()


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    """
    common_functions.determine_logging_level(args.verbose)

    if args.get_dd_file_name_from_dmt:
        file_name_from_dmt = get_dd_file_name_from_dmt(args.cluster_id)
        common_functions.print_to_screen(file_name_from_dmt, args.output_to_screen)

    if args.is_xml_format_new:
        file_name_from_dmt = get_dd_file_name_from_dmt(args.cluster_id)
        is_dd_xml_format_new = check_if_dd_xml_format_new(file_name_from_dmt)
        common_functions.print_to_screen(is_dd_xml_format_new, args.output_to_screen)

    if args.invert_dd_xml_format:
        inverted_dd_xml = invert_dd_xml_format(args.invert_dd_xml_format)
        common_functions.print_to_screen(inverted_dd_xml, args.output_to_screen)

    if args.get_xml_file_from_dmt:
        dir_and_file_from_dmt = get_xml_file_from_dmt(args.cluster_id)
        common_functions.print_to_screen(dir_and_file_from_dmt, args.output_to_screen)

    if args.get_new_dir_and_file_from_dmt:
        new_file_and_dir = get_new_dir_and_file_from_dmt(args.get_new_dir_and_file_from_dmt)
        common_functions.print_to_screen(new_file_and_dir, args.output_to_screen)


def get_dd_file_name_from_dmt(cluster_id):
    """
    This function finds the DD XML name from DMT based on the cluster id passed in
    :param cluster_id:
    :return dd_name
    """
    try:
        dd_data_from_dmt = json.loads(requests.get(DMT_DD_INFO_URL + cluster_id).content)
    except requests.exceptions.RequestException as request_exception:
        logging.error('Error making get request to DMT')
        logging.error('Request exception %s', request_exception)
        sys.exit(1)
    dd_name = dd_data_from_dmt['deployment_description_data']['auto_deployment']
    logging.debug('DD file name from DMT: %s', dd_name)
    return dd_name


def get_json_mapping_from_deploy_templates_endpoint():
    """
    This function queries the deployment templates DD XML endpoint stored in nexus
    for the different new to old mappings
    :return json_mapping_from_endpoint
    """
    try:
        logging.debug("Getting deployment templates XML mapping file from nexus")
        json_mapping_from_endpoint = json.loads(requests.get(JSON_MAPPING_URL).content)
        return json_mapping_from_endpoint
    except requests.exceptions.RequestException as request_exception:
        logging.error('Error making get request to deployment templates mapping endpoint')
        logging.error('Request exception %s', request_exception)
        sys.exit(1)


def invert_dd_xml_format(dd_xml_to_invert):
    """
    This function queries the input on the deployment templates XML mapping endpoint. If it's in a
    new format, it will return the same entry in an old format. If it's in an old format, it will
    return the same entry in a new format
    :param dd_xml_to_invert:
    :return inverted_xml
    """
    json_from_endpoint = get_json_mapping_from_deploy_templates_endpoint()
    mapping_data = json_from_endpoint["enm_dd_name_mapping"]
    for data in mapping_data:
        if data["dd_name"] == dd_xml_to_invert:
            return data["old_dd_name"]
        elif data["old_dd_name"] == dd_xml_to_invert:
            return data["dd_name"]
    logging.error("Unable to invert XML as unable to find mapping. Exiting...")
    sys.exit(1)


def check_if_dd_xml_format_new(dd_xml_to_check):
    """
    This function will check the passed in DD XML and return True if it is in a new format.
    It will return False if it is in an old format. If it can't find the dd_name, it assumes
    the XML is in a new format and just has not been added to the mapping file.
    :param dd_xml_to_check:
    :return Boolean
    """
    logging.info("From current DD XML of %s, determining if it is in an old or new format",
                 dd_xml_to_check)
    json_from_endpoint = get_json_mapping_from_deploy_templates_endpoint()
    mapping_data = json_from_endpoint["enm_dd_name_mapping"]
    for data in mapping_data:
        if data["dd_name"] == dd_xml_to_check:
            logging.info("DD XML passed in using new DD XML format")
            return True
        elif data["old_dd_name"] == dd_xml_to_check:
            logging.info("DD XML passed in using old DD XML format")
            return False
    logging.warning("Unable to determine if %s is using a new or old DD XML format. "
                    "Assuming it's in a new format.", dd_xml_to_check)
    return True


def get_xml_file_from_dmt(cluster_id):
    """
    This function queries DMT and finds if the DD XML format is new or old.
    If it is a new format, it will return the XML file name with the directory
    attached. If it is old, it will just return the XML file name
    :param cluster_id:
    :return dd_file_or_dir_from_dmt
    """
    dd_file_from_dmt = get_dd_file_name_from_dmt(cluster_id)
    if check_if_dd_xml_format_new(dd_file_from_dmt):
        return get_new_dir_and_file_from_dmt(dd_file_from_dmt)
    else:
        logging.info("DD XML file name in old format so no need to append directory")
        return dd_file_from_dmt


def get_new_dir_and_file_from_dmt(dd_file_from_dmt):
    """
    This function will get the deployment description directory and file for physical
    environments on new versions of deployment templates
    :param dd_file_from_dmt:
    :return:
    """
    logging.info("Appending directory name to DD XML file name as it is in a new format")
    mapping_data = get_json_mapping_from_deploy_templates_endpoint()
    for data in mapping_data["enm_dd_name_mapping"]:
        if data["dd_name"] == dd_file_from_dmt:
            return data["dd_dir"] + "/" + dd_file_from_dmt
    logging.warning("Unable to find directory name for DD XML file from mapping. Assuming "
                    "this is a new XML file and parsing XML name from DMT to find directory "
                    "structure.")
    dd_dir = dd_file_from_dmt.split("__")[0]
    return dd_dir + "/" + dd_file_from_dmt


if __name__ == "__main__":
    execute_functions(parse_args())