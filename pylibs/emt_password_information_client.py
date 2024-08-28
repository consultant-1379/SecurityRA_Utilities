"""
 This script communicates with EMT to retrieve
 passwords over REST.
"""
import logging
import sys

from requests import RequestException

import argparse
import MTELoopScripts.etc.pylibs.config as config
import MTELoopScripts.etc.pylibs.configuration as configuration

from MTELoopScripts.etc.pylibs.request_retry import request_retry
from MTELoopScripts.etc.pylibs.common_functions import determine_logging_level, print_to_screen

# pylint: disable=E1101
CONFIG = configuration.UtilsConfig()
EMT_API_URL = '{0}/api/environment-password-information/'.format(CONFIG.get('MT_Cloud', 'emt_url'))


def parse_args():
    """
    This function parses the passed in system arguments.
    :return parser.parse_args():
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    ------------
    This will retrieve the password for an environment

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -lp -en 339'
    ''' + sys.argv[0] + ''' -wp -en ieatenmc7a12'
    ''',
        epilog=''''''
    )
    parser.add_argument("-wp", "--wlvm_password",
                        help="Get the password for a wlvm",
                        action="store_true")
    parser.add_argument("-lp", "--lms_password",
                        help="Get the password for a ms",
                        action="store_true")
    parser.add_argument("-en", "--environment_name", dest="environment_name",
                        help="The environment to get the password from",
                        required=True)
    parser.add_argument("-s", "--set_new_password", dest="set_new_password",
                        help="Set the password in EMT")
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def get_environment_password_information_from_emt(environment_name):
    """
    This function will get password information from the EMT endpoint and return it as a
    json object
    :param environment_name: name of environment to get password information for
    :return: json object containing password information if it exists, otherwise None
    """
    try:
        return request_retry("GET", EMT_API_URL + environment_name, 5).json()
    except RequestException:
        logging.warning("Unable to find password information for environment {0}"
                        .format(environment_name))
        return None


def determine_wlvm_password_or_set_default(environment_name):
    """
    This function wil return the wlvmPassword key of the json object returned from the EMT
    endpoint. If there was in issue retrieving the information, it will default the password to
    12shroot
    :param environment_name: name of environment to get password information for
    :return: String containing wlvm password information
    """
    emt_response = get_environment_password_information_from_emt(environment_name)
    if emt_response is not None and 'wlvmPassword' in emt_response:
        return emt_response["wlvmPassword"]
    logging.info("Defaulting wlvmPassword to 12shroot")
    return "12shroot"


def determine_lms_password_or_set_default(environment_name):
    """
    This function wil return the lmsPassword key of the json object returned from the EMT
    endpoint. If there was in issue retrieving the information, it will default the password to
    12shroot
    :param environment_name: name of environment to get password information for
    :return: String containing lms password information
    """
    emt_response = get_environment_password_information_from_emt(environment_name)
    if emt_response is not None and 'lmsPassword' in emt_response:
        return emt_response["lmsPassword"]
    logging.info("Defaulting lmsPassword to 12shroot")
    return "12shroot"


def set_server_password_in_emt(environment_name, server_to_update, new_password):
    """
    This function will set the specified server password in EMT based on the new password
    passed in
    :param environment_name: name of environment to set password information for
    :param server_to_update: server to update password for in the same format it appears in EMT
    E.g. lmsPassword or wlvmPassword
    :param new_password: value of password to update in EMT
    :return:
    """
    password_information = {
        server_to_update: new_password,
        'username': 'Jenkins'
    }
    try:
        put_response = request_retry("PUT", EMT_API_URL + environment_name, 5,
                                     password_information)
        logging.info(put_response)
    except RequestException:
        logging.error("Unable to set {0} password in EMT for {1}"
                      .format(server_to_update, environment_name))
        sys.exit(1)


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    :param args
    """
    if args.verbose:
        determine_logging_level(args.verbose)
    if not args.wlvm_password and not args.lms_password:
        logging.error("You must specify a server type to search for")
        sys.exit(1)
    if args.wlvm_password:
        if args.set_new_password:
            set_server_password_in_emt(args.environment_name, "wlvmPassword",
                                       args.set_new_password)
        else:
            wlvm_password = determine_wlvm_password_or_set_default(args.environment_name)
            print_to_screen(wlvm_password, True)
    elif args.lms_password:
        if args.set_new_password:
            set_server_password_in_emt(args.environment_name, "lmsPassword",
                                       args.set_new_password)
        else:
            lms_password = determine_lms_password_or_set_default(args.environment_name)
            print_to_screen(lms_password, True)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())