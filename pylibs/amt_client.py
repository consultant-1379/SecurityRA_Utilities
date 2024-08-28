"""
 This script communicates with AMT to carry
 out any REST functions.
"""
import json
import logging
import sys

import MTELoopScripts.etc.pylibs.argparse as argparse
import MTELoopScripts.etc.pylibs.config as config
import MTELoopScripts.etc.pylibs.common_functions as common_functions
import MTELoopScripts.etc.pylibs.configuration as configuration
from MTELoopScripts.etc.pylibs.request_retry import request_retry

CONFIG = configuration.UtilsConfig()
AMT_API_URL = '{0}/api'.format(CONFIG.get('COMMON_VARIABLES', 'amt_url'))
SLOT_API_URL = '{0}/slots'.format(AMT_API_URL)
SWITCHBOARD_API_URL = '{0}/switchboard'.format(AMT_API_URL)
EXECUTE_POST_SLOT_ACTIONS_API_URL = '{0}/amt/execute-post-slot-actions'.format(AMT_API_URL)


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
    This will communicate with AMT to carry out any of the actions specified

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -cs -b '{
         "physicalEnvironment": "physicalEnv",
         "venmEnvironment": "cloudEnv",
         "deliveredDGs": [ { "deliveryGroupId": "42426",
         "createdByTeam": "Smart", "includedCategories": "ms" } ],
         "productSetVersion": "20.04.110",
         "venmStatus": "ongoing",
         "physicalStatus": "ongoing",
         "slotStatus": "ongoing"
        }'
    ''' + sys.argv[0] + ''' -f '{
        "physicalEnvironment": "306",
        "slotStatus": "ongoing",
        "venmEnvironment": "ieatenmc3b10"}'
    ''' + sys.argv[0] + ''' --update_amt_slot --request_body '{
        "physicalEnvironment": "306",
        "slotStatus": "success",
        "venmEnvironment": "ieatenmc3b10"}'
    ''' + sys.argv[0] + ''' -s --request_body '{
        "amt_trigger_status": "on",
        "delivery_group_obsoletion_status": "off",
        "upgrade_slot_mechanism_status": "parallel"}'
    ''',
        epilog=''''''
    )
    parser.add_argument("-cs", "--create_amt_slot",
                        help="Creates an AMT slot based on the properties passed in by the request"
                             " body parameter", action="store_true")
    parser.add_argument("-f", "--find_amt_slot_id",
                        help="Finds one AMT slot based on the search criteria passed in. It will "
                             "fail if more than one slot is found with the given search criteria.")
    parser.add_argument("-s", "--update_amt_switchboard",
                        help="Updates the AMT switchboard with the properties passed in by "
                             "the request body parameter", action="store_true")
    parser.add_argument("-us", "--update_amt_slot",
                        help="Updates the AMT slot based on the slot ID passed in with the "
                             "properties passed in by the request body parameter")
    parser.add_argument("-ps", "--execute_post_slot_actions",
                        help="Updates the AMT slot based on the slot ID passed in with the "
                             "properties passed in by the request body parameter and triggers all"
                             "post slot actions")
    parser.add_argument("-b", "--request_body",
                        help="Request body to be used in PATCH/POST requests")
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def create_amt_slot(request_body):
    """
    This function creates an AMT slot based on the properties specified in the request body
    :param request_body the properties for the slot that will be created
    :return: Request response
    """
    if not request_body:
        logging.error("Request body must be passed in when creating a slot.")
        sys.exit(1)
    amt_request_body = json.loads(request_body)
    logging.debug('amt_request_body: ' + str(amt_request_body))
    response = request_retry("POST", SLOT_API_URL, 5, amt_request_body)
    logging.info(response)
    return response


def update_amt_slot(slot_id, request_body):
    """
    This function updates an AMT slot with the properties specified in the request body
    :param slot_id ID of the slot to update
    :param request_body the properties for the slot that will be updated
    :return: Request response
    """
    if not request_body:
        logging.error('Request body must be passed in when updating a slot.')
        sys.exit(1)
    amt_request_body = json.loads(request_body)
    logging.debug('amt_request_body: ' + str(amt_request_body))
    amt_slot_put_url = '{0}/{1}'.format(SLOT_API_URL, slot_id)
    patch_response = request_retry("PATCH", amt_slot_put_url, 5, amt_request_body)
    if not patch_response:
        logging.error('Something went wrong while trying to update an AMT slot. Exiting.')
        sys.exit(1)
    logging.info(patch_response)
    return patch_response


def trigger_post_slot_actions_in_amt(slot_id, request_body):
    """
    This function triggers the post slot actions in AMT by using the properties specified
    in the request body
    :param slot_id ID of the slot to trigger post slot actions for
    :param request_body the properties for the slot that will trigger post slot actions for
    :return: Request response
    """
    if not request_body:
        logging.error('Request body must be passed in when triggering post slot actions.')
        sys.exit(1)
    try:
        amt_request_body = json.loads(request_body)
    except ValueError:
        logging.error('Request body must be valid JSON! Exiting...')
        sys.exit(1)
    logging.debug('amt_request_body: ' + str(amt_request_body))
    amt_slot_put_url = '{0}/{1}'.format(EXECUTE_POST_SLOT_ACTIONS_API_URL, slot_id)
    patch_response = request_retry("PATCH", amt_slot_put_url, 5, amt_request_body)
    if not patch_response:
        logging.error('Something went wrong while trying to trigger post slot actions. Exiting.')
        sys.exit(1)
    logging.info(patch_response)
    return patch_response


def update_amt_switchboard(request_body):
    """
    This function updates an AMT switchboard with the properties specified in the request body
    :param request_body the properties for the switchboard that will be updated
    :return: Request response
    """
    if not request_body:
        logging.error('Request body must be passed in when updating a switchboard.')
        sys.exit(1)
    try:
        amt_request_body = json.loads(request_body)
    except ValueError:
        logging.error('Request body must be valid JSON! Exiting...')
        sys.exit(1)
    logging.debug('amt_request_body: ' + str(amt_request_body))
    patch_response = request_retry("PATCH", SWITCHBOARD_API_URL, 5, amt_request_body)
    logging.info(patch_response)
    return patch_response


def find_amt_slot_id(search_criteria):
    """
    This function finds the ID of an AMT slot based on the search criteria passed in
    :param search_criteria properties of the slot to look for
    :return: Either the ID of the slot found or None if no slot found
    """
    if not search_criteria:
        logging.error('Search criteria must be passed in when searching for slot ID.')
        sys.exit(1)
    search_query = generate_search_query(json.loads(search_criteria))
    amt_slot_search_url = '{0}/search?{1}'.format(SLOT_API_URL, search_query)
    slots_matching_search_criteria = request_retry("GET", amt_slot_search_url, 5)\
        .json()
    if not slots_matching_search_criteria:
        logging.warn('No slot found with the given search criteria')
        return None
    if len(slots_matching_search_criteria) > 1:
        logging.error('Got more than one slot ID back. Please refine your search criteria further.')
        sys.exit(1)
    return slots_matching_search_criteria[0]['id']


def generate_search_query(search_criteria):
    """
    This function generates a search query to use in AMT search API from passed in search criteria
    :param search_criteria properties of the slot to look for
    :return: the search query
    """
    search_query = ''
    logging.debug('Search criteria: ' + str(search_criteria))
    for criteria_key, criteria_value in search_criteria.items():
        if search_query:
            search_query += '&'
        search_query += '{0}={1}'.format(criteria_key, criteria_value)
    logging.debug('Search query: ' + search_query)
    return search_query


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    :param args
    """
    if args.verbose:
        common_functions.determine_logging_level(args.verbose)
    if args.create_amt_slot:
        create_amt_slot(args.request_body)
    if args.update_amt_slot:
        update_amt_slot(args.update_amt_slot, args.request_body)
    if args.find_amt_slot_id:
        slot_id = find_amt_slot_id(args.find_amt_slot_id)
        if slot_id:
            logging.info('Found slot ID: {0}'.format(slot_id))
            print(slot_id)
    if args.update_amt_switchboard:
        update_amt_switchboard(args.request_body)
    if args.execute_post_slot_actions:
        trigger_post_slot_actions_in_amt(args.execute_post_slot_actions, args.request_body)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())