"""This script retrieves the cluster id that corresponds to a DIT deployment"""
import logging
import sys
import argparse

import config

from configuration import FTPConfigReader
from cloud_mapper import CloudMappingJSONReader


def _parse_args():
    """ This function parses the passed in system arguments.
    :return arguments object
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Description: Given a a known DIT deployment, this script returns the corresponding dummy DMT cluster id.',
        epilog='Examples: -> ' + sys.argv[0] + ' -d ieatenmpca08 -o'
    )
    parser.add_argument("-d", "--deployment_name",
                        help="The DIT deployment name to lookup its cluster id",
                        required=True)
    parser.add_argument("-v", "--verbose",
                        help="Set output verbosity to debug",
                        action="store_true")
    parser.add_argument("-o", "--output_to_screen",
                        help="Option to output the value to screen", nargs='?',
                        const=True)
    parser.add_argument("-r", "--print_to_screen",
                        help="Option to print the value to screen", nargs='?',
                        const=True)
    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        parser.exit()
    return parser.parse_args()


def _invoke_cli(args):
    logging.info("Retrieving deploymentMappings.json from FTP")
    cloud_config = FTPConfigReader()
    deployment_mapping_url = cloud_config.deployment_mappings_url
    reader = CloudMappingJSONReader(deployment_mapping_url)
    dmt_id = reader.get_dmt_id_for_cloud_deployment(args.deployment_name)
    return dmt_id


def _toggle_verbose(args):
    """If verbose argument is present, it will turn on verbose"""
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    config.console.setLevel(level)


def _execute_logic():
    args = _parse_args()
    _toggle_verbose(args)
    print(_invoke_cli(args))


if __name__ == "__main__":
    config.init(__file__)
    _execute_logic()