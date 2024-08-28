"""
This is used as a client to product_set.py
"""

import logging
import sys

# disable=relative-import
import argparse
import common_functions
import config

from product_set import ProductSet


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    This script is used to create a client between a script and the
    python modules in product_set.py.

    It queries the CI portal to obtain product set information.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -p 17.16.11 -pn CXP9026759,CXP9026826
      -> ''' + sys.argv[0] + ''' -p 17.16.11 -en CXP9031559
      -> ''' + sys.argv[0] + ''' -p 17.16.11 -vn CXP9032490 -j
      -> ''' + sys.argv[0] + ''' -p 18.09.19 -d 18.09 -i
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-p", "--product_set",
                        help="Product Set version of the "
                             "content you wish to query for")
    parser.add_argument("-d", "--drop",
                        help="Drop of the "
                             "content you wish to query for")
    parser.add_argument("-pn", "--products_nexus",
                        help="Obtain Nexus URLs for specified products")
    parser.add_argument("-en", "--enm_artifacts_nexus",
                        help="Obtain Nexus URLs for specified ENM artifacts")
    parser.add_argument("-vn", "--vnflcm_artifacts_nexus",
                        help="Obtain Nexus URLs for specified "
                             "VNFLCM artifacts")
    parser.add_argument("-j", "--create_json_for_nwci",
                        help="Create artifact JSON for NWCI deploy",
                        action="store_true")
    parser.add_argument("-i", "--return_iso",
                        help="Return ISO from product set",
                        action="store_true")
    parser.add_argument("-c", "--product_set_contents_version",
                        help="Return content version from product set")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def execute_functions(args):
    """
    :param args: Argument list returned by arg parser
    Executes the functions in the script
    """
    common_functions.determine_logging_level(args.verbose)

    artifacts = {}

    if args.product_set:
        logging.info("Product set: " + str(args.product_set))
        product_set = ProductSet(args.product_set)

    if args.products_nexus:
        list_of_products = args.products_nexus.split(",")
        artifacts.update(product_set.obtain_product_set_content(
            list_of_products, "hubUrl"))

    if args.enm_artifacts_nexus:
        enm_json = product_set.get_artifact_content(product_set.
                                                    ENM_ISO_ARTIFACT,
                                                    product_set.enm_version)
        list_of_enm_artifacts = args.enm_artifacts_nexus.split(",")
        artifacts.update(product_set.obtain_artifact_content_nexus_urls(
            enm_json,
            list_of_enm_artifacts))

    if args.vnflcm_artifacts_nexus:
        enm_json = product_set.get_artifact_content(
            product_set.VNFLCM_ARTIFACT,
            product_set.vnflcm_version)
        list_of_vnflcm_artifacts = args.vnflcm_artifacts_nexus.split(",")
        artifacts.update(product_set.obtain_artifact_content_nexus_urls(
            enm_json,
            list_of_vnflcm_artifacts))

    if args.create_json_for_nwci:
        artifact_json = product_set.create_json_for_nwci(artifacts)
        print artifact_json

    if args.return_iso:
        iso_version = product_set.get_enm_iso(args.drop)
        print iso_version

    if args.product_set_contents_version:
        content_version = product_set.get_artifact_version(args.product_set_contents_version)
        print content_version


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())