"""
 This script is used to retrieve info from a jobs JSON file
"""

import logging
import sys

import common_functions
import config
import argparse
import configuration
from MTELoopScripts.etc.pylibs.lib.emt import emt_core
from MTELoopScripts.etc.pylibs.lib.utils.url import UrlBuilder

CONFIG = configuration.UtilsConfig()


class JobJsonKeyNotFound(Exception):
    pass


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
    This will go to the json of a specified jenkins job.
    A key can be provided to specify what info you want.
    Examples:
    ------------
    ''' + sys.argv[0] + ''' -j http: some_job_url -k result
    ''',
        epilog=''''''
    )
    parser.add_argument("-j", "--job_url",
                        help="State of the deployment",
                        required=True)
    parser.add_argument("-k", "--key_to_search",
                        help="Assigned job of the deployment",
                        required=True)
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")

    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def retrieve_key_value(job_json, key_to_search):
    """
    This function is used to get the value from a key pair in the job JSON
    :param job_json: json object retrieved from retrieve_job_api_json
    :param key_to_search: key to search through job json for
    :return: key_value
    """
    try:
        key_value = job_json[key_to_search]
        if key_value:
            return key_value
        else:
            logging.error("Couldn't retrieve value for '" + key_to_search +
                          "' key passed in")
            logging.error("Exiting...")
    except (ValueError, IndexError):
        raise JobJsonKeyNotFound("Could not fetch key value from job json "
                                 "during json decoding stage")


def retrieve_job_api_json(job_build_url):
    """
    This function opens the url request to get the jobs json file
    :param job_build_url: jenkins job build url gotten using bash
    :return: json_response
    """
    logging.info("Attempting to retrieve job api JSON...")
    builder = UrlBuilder(job_build_url).append_path("api/json")
    url = builder.url
    logging.info(url)
    json_response = emt_core.get(url)
    if json_response:
        return json_response
    else:
        logging.error("Couldn't retrieve JSON response for '" +
                      job_build_url + "' URL passed in")


def parse_job_json(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    """
    common_functions.determine_logging_level(args.verbose)
    job_json = retrieve_job_api_json(args.job_url)
    logging.debug("Job JSON: " + str(job_json))

    job_result = retrieve_key_value(job_json, args.key_to_search)
    common_functions.print_to_screen(job_result, True)
    return job_result


if __name__ == "__main__":
    config.init(__file__)
    parse_job_json(parse_args())