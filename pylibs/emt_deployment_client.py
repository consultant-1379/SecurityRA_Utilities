"""
 This script communicates with EMT to carry
 out any deployment related functions.
"""
import sys
import logging
import json

import MTELoopScripts.etc.pylibs.argparse as argparse
import MTELoopScripts.etc.pylibs.config as config
import MTELoopScripts.etc.pylibs.common_functions as common_functions
import MTELoopScripts.etc.pylibs.configuration as configuration

from MTELoopScripts.etc.pylibs.lib.emt.deployments.module \
    import EMTDeploymentsModule

EMT_DEP_MOD = EMTDeploymentsModule()
CONFIG = configuration.UtilsConfig()


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
    This will communicate with EMT in various ways depending
    on the args passed in.
    You can pass in multiple args to this script.
    Each operation will be completed in isolation.
    For example if you want to update multiple fields in your DB
    this script will execute multiple REST events to facilitate

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -c ieatenmpca05 --set_property "state" "BUSY"
    -u ERTSHUE
    ''' + sys.argv[0] + ''' -c ieatenmpca05 --get_property "state"
    ''' + sys.argv[0] + ''' --find_environment_names_based_on_search_criteria "{ "testPhase": "RTD" }"
    ''' + sys.argv[0] + ''' --find_environment_names_based_on_search_criteria "{ "testPhase": "RTD%MTE" }"
    ''' + sys.argv[0] + ''' --find_environment_names_based_on_search_criteria "{ "testPhase": "RTD",
    "platformType": "physical" }"
    ''',
        epilog=''''''
    )
    parser.add_argument("-c", "--cluster_id",
                        help="Cluster Id of the deployment")
    parser.add_argument("-s", "--set_property", nargs=2,
                        help="Set the property on an EMT deployment")
    parser.add_argument("-g", "--get_property",
                        help="Get the property of an EMT deployment")
    parser.add_argument("-u", "--username",
                        help="Username of the person doing a PUT request. "
                             "Required if updating an environment property")
    parser.add_argument("-fn", "--find_environment_names_based_on_search_criteria",
                        help="This will return a list of environments from EMT based on the "
                             "search criteria passed in")
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def set_deployment_property(cluster_id, key_to_set, value_to_set, username):
    """
    Update an emt deployments property value_to_set
    :param cluster_id: The deployment name
    :param key_to_set: The deployment property to update
    :param value_to_set: The value of the property to be set
    :param username: username of who is setting property
    """
    deployment = EMT_DEP_MOD.query("name=" + cluster_id)
    if deployment:
        deployment_emt_id = deployment[0]
        response = EMT_DEP_MOD.property_setter(deployment_emt_id,
                                               key_to_set, value_to_set,
                                               username)
        logging.info(response)
    else:
        logging.warn("Cluster ID " + cluster_id + " not found in "
                     "EMT. Did not set property: " + key_to_set)


def get_deployment_property(cluster_id, key_to_get):
    """
    Get an EMT deployments property
    :param cluster_id:
    :param key_to_get:
    :return:
    """
    deployment = EMT_DEP_MOD.query("name=" + cluster_id)
    if deployment:
        deployment_emt_id = deployment[0]
        desired_key_value = getattr(deployment_emt_id, key_to_get)
        logging.info(key_to_get + " = " + desired_key_value)
        return desired_key_value
    else:
        logging.warn("Cluster ID " + cluster_id + " not found in "
                     "EMT. Did not get property: " + key_to_get)
        return None


def find_environments_from_query(search_criteria):
    """
    This function finds a list of EMT environments based on the search criteria passed in
    :param search_criteria properties of the environments to look for
    :return: Comma separated list of environments or None if no environment found
    """
    if not search_criteria:
        logging.error('Search criteria must be passed in while searching for environments.')
        sys.exit(1)
    try:
        search_criteria = json.loads(search_criteria)
    except ValueError:
        logging.error('Search criteria must be a valid JSON object')
        sys.exit(1)

    search_query = generate_search_query(search_criteria)
    environments = EMT_DEP_MOD.query(search_query)
    if not environments:
        return None
    list_of_environments = ''
    for environment in environments:
        list_of_environments += environment.name + ','
    return list_of_environments[:-1]


def generate_search_query(search_criteria):
    """
    This function generates a search query to use in EMT search API from passed in search criteria
    :param search_criteria properties of the environments to look for
    :return: the search query
    """
    search_query = ''
    logging.debug('Search criteria: ' + str(search_criteria))
    for criteria_key, criteria_value in search_criteria.items():
        if search_query:
            search_query += '&q='
        search_query += '{0}={1}'.format(criteria_key, criteria_value)
    logging.debug('Search query: ' + search_query)
    return search_query


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    """
    if args.verbose:
        common_functions.determine_logging_level(args.verbose)
    elif args.set_property:
        key_value_pair = args.set_property
        if not args.username:
            logging.error("Please pass in a username when setting an "
                          "environment property")
            sys.exit(1)
        username = args.username
        set_deployment_property(args.cluster_id,
                                key_value_pair[0],
                                key_value_pair[1],
                                username)
    elif args.get_property:
        common_functions.print_to_screen(
            get_deployment_property(args.cluster_id, args.get_property), True)
    elif args.find_environment_names_based_on_search_criteria:
        retrieved_environments = find_environments_from_query(
            args.find_environment_names_based_on_search_criteria)
        common_functions.print_to_screen(retrieved_environments, True)
    else:
        logging.error("Something went wrong. Exiting...")
        sys.exit(1)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())