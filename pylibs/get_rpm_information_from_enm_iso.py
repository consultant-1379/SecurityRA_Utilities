import logging
import sys
import urllib

import config
import argparse
import common_functions
import configuration

"""
    This script retrieves the version of an rpm
    or list of RPMs from a given ENM ISO.

"""

CONFIG = configuration.UtilsConfig()


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
    This script retrieves the version of an rpm
    or list of RPMs from a given ENM ISO

    Examples:
    ------------
    ''' + sys.argv[0] + ''' --iso_version 1.37.54 --list_of_rpms ERICrpm
    ''' + sys.argv[0] + ''' --iso_version 1.37.54 --list_of_rpms ERICrpm1,ERICrpm1
    ''',
        epilog=''''''
    )
    parser.add_argument("-i", "--iso_version",
                        help="Version of the ENM ISO to search")
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-l", "--list_of_rpms",
                        help="Comma separate list of RPMs to retrieve the "
                             "version from the ISO")
    parser.add_argument("-p", "--print_to_screen",
                        help="Option to print the value to screen", nargs='?',
                        const=True)

    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def get_json_data(iso_version):
    """
    :param iso_version: Version of the ENM ISO
    :return: JSON Object with ISO Content
    """
    url_parameters = {"isoName": CONFIG.get("COMMON_VARIABLES", "enm_iso"), "isoVersion": iso_version,
                      "pretty": "true"}
    url = urllib.urlencode(url_parameters)
    iso_content_rest_call = CONFIG.get("COMMON_VARIABLES", "cifwk_url") + "/getPackagesInISO/?" + url
    iso_content_html_response = common_functions.return_url_response(
        iso_content_rest_call)
    iso_content_data = common_functions.return_json_object(
        iso_content_html_response)

    return iso_content_data


def get_version_of_rpm(rpm_name, iso_version):
    """
    :param rpm_name: Name of rpm
    :param iso_version: Version of ENM ISO
    :return: Version of the RPM if found in ISO.
    None if not found
    """
    logging.info("Finding Version for " + str(rpm_name) + " in ISO " +
                 str(iso_version))
    json_object = get_json_data(iso_version)
    if type(json_object) is dict:
        for key_found in json_object:
            if key_found == "PackagesInISO":
                iso_content = json_object[key_found]
                for package in iso_content:
                    if rpm_name in package['name']:
                        logging.info(rpm_name + " found in ISO")
                        version = package['version']
                        logging.info("Version = " + version)
                        if args.print_to_screen:
                            print version
                        return version
    logging.error("Unable to find Version for " + rpm_name)


def check_valid_iso_version(version):
    """
    :param version: ISO Version
    Checks if the ISo Version is a valid version in the following format X.X.X,
    where X is a digit.
    """
    valid_version = version.split(".")
    if len(valid_version) == 3:
        if all(version_numbers.isdigit() for version_numbers in valid_version):
            logging.info(sys.argv[2] + " is a valid ISO Version")
        else:
            logging.error("Invalid ISO Version Passed in")
            sys.exit(1)
    else:
        logging.error("Argument is not valid. "
                      "Please pass in a valid ISO Version")
        sys.exit(1)


def validate_arguments():
    """
    :return: Return the value to be searched.
    """

    list_of_rpms = None
    iso_version = None

    if args.verbose:
        config.console.setLevel(logging.DEBUG)
    else:
        config.console.setLevel(logging.INFO)

    if args.iso_version:
        iso_version = args.iso_version
        check_valid_iso_version(iso_version)
        logging.debug("ISO Version = " + iso_version)

    if args.list_of_rpms:
        list_of_rpms = args.list_of_rpms
        logging.debug("List of RPMS = " + list_of_rpms)

    if list_of_rpms and iso_version:
        return list_of_rpms, iso_version
    else:
        logging.error("Unable to get arguments")
        sys.exit(1)

if __name__ == "__main__":
    config.init(__file__)
    args = parse_args()
    rpms, enm_iso_version = validate_arguments()
    for rpm in rpms.split(','):
        rpm_version = get_version_of_rpm(rpm, enm_iso_version)