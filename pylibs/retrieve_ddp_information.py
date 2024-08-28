#!/usr/bin/env python
"""
    This script retrieves DDP information based on the parameters passed into
    it. It can retrieve the DDP associated with a cluster ID. It can retrieve
    the port number for a given deployment.
"""

import logging
import sys
import argparse

import common_functions
import config
import configuration
import requests
import json

requests.packages.urllib3.disable_warnings()

CONFIG = configuration.UtilsConfig()

DMT_URL = CONFIG.get("COMMON_VARIABLES", "cifwk_url")
DMT_ADDITIONAL_PROPERTIES_URL = DMT_URL + "/api/deployment/" \
                                              "getClusterAdditionalProperties/clusterId/"


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    This script will retrieve DDP information for a deployment
    based on the arguments passed into it.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -d 306 -v
      -> ''' + sys.argv[0] + ''' -d 306 -p 306 -o
      -> ''' + sys.argv[0] + ''' -c 306 -o
      -> ''' + sys.argv[0] + ''' -i ieatenmpca08 -o
      -> ''' + sys.argv[0] + ''' -a 306
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-d", "--get_ddp_server",
                        help="For a given cluster ID, returns the DDP server "
                             "associated with that deployment.")
    parser.add_argument("-p", "--get_ddp_port",
                        help="For a given cluster ID, returns the DDP server "
                             "port associated with that deployment.")
    parser.add_argument("-c", "--get_cron",
                        help="For a given cluster ID, returns the cron"
                             " information "
                             "associated with that deployment.")
    parser.add_argument("-o", "--output_to_screen",
                        help="Option to output the value to screen", nargs='?',
                        const=True)
    parser.add_argument("-a", "--search_all",
                        help="For a given cluster ID, returns all DDP"
                             "information for that deployment.")

    if not sys.argv:
        logging.error("No arguments passed in")
        parser.print_help()
        parser.exit()
    return parser.parse_args()


def toggle_verbose():
    """
    If verbose argument is present, it will turn on verbose
    """
    if args.verbose:
        config.console.setLevel(logging.DEBUG)
    else:
        config.console.setLevel(logging.INFO)


def validate_arguments():
    """
    This function prints the relevant value based on the system arguments.
    """
    if args.get_ddp_server:
        ddp_server_name = \
            get_specific_deployment_detail(args.get_ddp_server, "ddp_hostname")
        common_functions.print_to_screen(ddp_server_name,
                                         args.output_to_screen)

    if args.get_ddp_port:
        ddp_port = \
            get_specific_deployment_detail(args.get_ddp_port, "port")
        common_functions.print_to_screen(ddp_port, args.output_to_screen)

    if args.get_cron:
        cron = \
            get_specific_deployment_detail(args.get_cron, "cron")
        common_functions.print_to_screen(cron, args.output_to_screen)

    if args.search_all:
        ddp_server_name = \
            get_specific_deployment_detail(args.search_all, "ddp_hostname")
        common_functions.print_to_screen(ddp_server_name,
                                         args.output_to_screen)
        ddp_port = \
            get_specific_deployment_detail(args.search_all, "port")
        common_functions.print_to_screen(ddp_port, args.output_to_screen)
        cron = \
            get_specific_deployment_detail(args.search_all, "cron")
        common_functions.print_to_screen(cron, args.output_to_screen)


def get_specific_deployment_detail(deployment_name, info_to_search):
    """
    :param deployment_name: Name of the Deployment
    :param info_to_search: Item to search for that deployment
    :return: Return detail if detail for deployment was found.
    """
    logging.info("Retrieving " + str(info_to_search) + " for " +
                 str(deployment_name) + "...")
    try:
        dmt_additional_data = json.loads(requests.get(DMT_ADDITIONAL_PROPERTIES_URL +
                                                      deployment_name).content)
        logging.info("Found the following data in DMT: %s", dmt_additional_data)
        return dmt_additional_data[info_to_search]
    except requests.exceptions.RequestException as request_exception:
        logging.error('Error making request to DMT')
        logging.error('Request exception %s', request_exception)
        sys.exit(1)
    except KeyError as key_error_exception:
        logging.error('Invalid key provided')
        logging.error('Key exception %s', key_error_exception)
        sys.exit(1)


if __name__ == "__main__":
    config.init(__file__)
    args = parse_args()
    toggle_verbose()
    validate_arguments()