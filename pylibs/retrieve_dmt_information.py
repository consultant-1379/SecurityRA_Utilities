"""
    This script retrieves DMT information based on the parameters passed into
    it. It can retrieve the list of netsim servers and the other remaining
    servers for a given deployment. It can retrieve the cluster information
    for a given deployment. It can retrieve the MS IP for a given deployment.
    It can retrieve the Workload VM IP for a given deployment.
"""

import logging
import sys
import json

import argparse
import common_functions
import config
import configuration

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
    This script will retrieve DMT information for a deployment
    based on the arguments passed into it.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -s 306 -v
      -> ''' + sys.argv[0] + ''' -s 306 -m 306 -v
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-s", "--search_for_servers",
                        help="For a given cluster ID, returns a list of netsim"
                             " servers and a list of the rest of the remaining"
                             " servers.")
    parser.add_argument("-n", "--search_for_netsim_servers",
                        help="For a given cluster ID, returns a list of "
                             "netsim servers for that deployment.")
    parser.add_argument("-c", "--search_for_cluster_information",
                        help="For a given cluster ID, returns how many nodes"
                             " and the type of nodes for that deployment.")
    parser.add_argument("-m", "--search_for_ms_ip",
                        help="For a given cluster ID, returns the MS IP for"
                             " that deployment.")
    parser.add_argument("-w", "--search_for_workload_vm_ip",
                        help="For a given cluster ID, returns the Workload VM"
                             " IP for that deployment.")
    parser.add_argument("-a", "--search_all",
                        help="For a given cluster ID, returns all DMT"
                             "information for that deployment.")
    parser.add_argument("-r", "--print_to_screen",
                        help="Option to print the value to screen", nargs='?',
                        const=True)

    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        parser.exit()
    return parser.parse_args()


def validate_arguments():
    """
    :param args:
    :return:
    This function returns the relevant value based on the system arguments.
    """
    if args.verbose:
        config.console.setLevel(logging.DEBUG)
    else:
        config.console.setLevel(logging.INFO)

    if args.search_for_servers:
        netsim, servers = search_for_servers(args.search_for_servers)
        return netsim, servers

    if args.search_for_netsim_servers:
        search_for_netsim_servers(args.search_for_netsim_servers)

    if args.search_for_cluster_information:
        cluster_info = \
            search_for_cluster_information(args.search_for_cluster_information)
        return cluster_info

    if args.search_for_ms_ip:
        ms_ip = search_for_ms_ip(args.search_for_ms_ip)
        if ms_ip is None:
            ms_ip = ""
        common_functions.print_to_screen(ms_ip, args.print_to_screen)
        return ms_ip

    if args.search_for_workload_vm_ip:
        workload_vm_ip = \
            search_for_workload_vm_ip(args.search_for_workload_vm_ip)
        if workload_vm_ip is None:
            workload_vm_ip = ""
        common_functions.print_to_screen(workload_vm_ip, args.print_to_screen)
        return workload_vm_ip

    if args.search_all:
        netsim, servers = search_for_servers(args.search_all)
        cluster_info = \
            search_for_cluster_information(args.search_all)
        ms_ip = search_for_ms_ip(args.search_all)
        workload_vm_ip = \
            search_for_workload_vm_ip(args.search_all)
        return netsim, servers, cluster_info, ms_ip, workload_vm_ip


def validate_responses(response, response_type):
    """
    :param response:
    :param response_type:
    This function checks the response. It outputs an error message
    if the response is empty
    """
    if not response:
        logging.error("Error getting " + response_type + " response")
        sys.exit(1)


def search_for_servers(cluster_id):
    """
    :param cluster_id:
    :return netsim_servers, servers:
    This function retrieves two lists. The first
    list it retrieves is the list of netsims and
    the second list is a list of the remaining
    servers for that given deployment.
    """
    logging.info("Retrieving servers for " + str(cluster_id) + "...")
    servers = []
    netsim_servers = []
    json_returned = cluster_id_json_object(cluster_id)
    for row_of_information_for_deployment in json_returned:
        for key, value in row_of_information_for_deployment.iteritems():
            if "hostname" in key:
                if "netsim" not in value:
                    servers.append(value)
                else:
                    netsim_servers.append(value)
    logging.info("Netsim Servers for " + str(cluster_id) + ": " +
                 str(netsim_servers))
    logging.info("Other Servers for " + str(cluster_id) + ": " + str(servers))
    return netsim_servers, servers


def search_for_netsim_servers(cluster_id):
    """
    :param cluster_id:
    :return netsim_servers:
    This function retrieves a list of netsims for that given deployment.
    """
    logging.info("Retrieving netsim servers for " + str(cluster_id) + "...")
    netsim_servers = []
    json_returned = cluster_id_json_object(cluster_id)
    for row_of_information_for_deployment in json_returned:
        for key, value in row_of_information_for_deployment.iteritems():
            if "hostname" in key:
                if "netsim" in value:
                    netsim_servers.append(value)
                    print value
    logging.info("Netsim Servers for " + str(cluster_id) + ": " +
                 str(netsim_servers))
    return netsim_servers


def search_for_cluster_information(cluster_id):
    """
    :param cluster_id:
    :return cluster_info:
    This function returns a dictionary with
    the key being the cluster_id and the value
    being the list of nodes for that given deployment.
    """
    logging.info("Retrieving cluster information for " + str(cluster_id) +
                 "...")
    cluster_types = json.loads(CONFIG.get("COMMON_VARIABLES", "cluster_types"))
    cluster_list_returned_from_dmt = []
    clusters = []
    json_returned = cluster_id_json_object(cluster_id)
    for entry in json_returned:
        for attribute, value in entry.iteritems():
            if "hostname" in attribute:
                for cluster in cluster_types:
                    if cluster in value:
                        cluster_list_returned_from_dmt.append(value)
    node_count = 0
    for cluster_type in cluster_types:
        for cluster in cluster_list_returned_from_dmt:
            if cluster.find(cluster_type) != -1:
                node_count += 1
        if node_count == 0:
            continue
        clusters.append(str(node_count) + cluster_type + "_")
        returned_clusters = ''.join(clusters)
        node_count = 0
    logging.info("Cluster Information for " + str(cluster_id) + ": " +
                 str(returned_clusters))
    return returned_clusters


def search_for_ms_ip(cluster_id):
    """
    :param cluster_id:
    :return ms_ip:
    This function searches for and returns
    the IP of the MS by passing in the associated
    cluster ID.
    """
    logging.info("Retrieving MS IP for " + str(cluster_id) + "...")
    json_returned = cluster_id_json_object(cluster_id)
    for item in json_returned:
        if type(item) is dict:
            for key, value in item.items():
                if key == 'hostname' and value == 'ms1':
                    ms_ip = item['ip']
                    logging.info("MS IP for " + str(cluster_id) + ": " +
                                 str(ms_ip))
                    return ms_ip
    logging.info("MS IP cannot be obtained for " + str(cluster_id))


def retrieve_taf_troubleshooting_user_details_from_dmt(cluster_id):
    """
    This function searches for and returns
    the username and password of the TAF troubleshooting user designed to be used by TAF testware.
    :param cluster_id:
    :return taf_username, taf_password:
    """
    logging.info("Retrieving TAF user troubleshooting credentials for " + str(cluster_id) + "...")
    json_returned = cluster_id_json_object(cluster_id)
    for item in json_returned:
        if type(item) is dict:
            for key, value in item.items():
                if key == 'hostname' and value == 'ms1':
                    user_credentials = item['users']
                    logging.debug(user_credentials)
                    for user_credential in user_credentials:
                        taf_username = user_credential['username']
                        taf_password = user_credential['password']
                        logging.debug("taf_username : " + taf_username)
                        logging.debug("taf_password : " + taf_password)
                        if taf_username == "taf_user":
                            return taf_username, taf_password
    logging.error("TAF troubleshooting user credentials cannot be obtained for " +
                  str(cluster_id))
    sys.exit(1)


def search_for_workload_vm_ip(get_json_object, is_first=True):
    """
    :param get_json_object:
    :param is_first:
    :return workload_ip:
    This function searches for the VM IP through
    the use of recursion. First the cluster ID
    is passed into this function with a flag set
    as True(is_first). It then gets the JSON object and begins
    the search. When the function begins to recursively
    call itself, the flag is set to false as its the
    JSON object that is being passed into the function,
    not the cluster ID.
    """
    if is_first:
        logging.info(
            "Retrieving Workload VM IP for " + str(get_json_object) + "...")
        cluster_id = get_json_object
        json_returned = cluster_id_json_object(cluster_id)
    else:
        json_returned = get_json_object
    if type(json_returned) is dict:
        for key_found in json_returned:
            if key_found == "type":
                if json_returned[key_found] == "workload":
                    list_of_interfaces = json_returned["interfaces"]
                    for interface in list_of_interfaces:
                        if interface["type"] == "public":
                            workload_ip = interface["ipv4"]
                            if not workload_ip:
                                workload_ip = "No IP address found"
                            return workload_ip
            workload_ip = search_for_workload_vm_ip(json_returned[key_found],
                                                    is_first=False)
    elif type(json_returned) is list:
        for item in json_returned:
            if type(item) in (list, dict):
                workload_ip = search_for_workload_vm_ip(item, is_first=False)
                if workload_ip:
                    logging.info("Workload VM IP for " + str(cluster_id) +
                                 ": " + str(workload_ip))
                    return workload_ip


def cluster_id_json_object(cluster_id):
    """
    :param cluster_id:
    :return json_returned:
    This function returns the JSON object that is
    retrieved from the CIFWK REST call that uses
    the passed in cluster ID for the URL.
    """
    cluster_id_rest_call = \
        CONFIG.get("COMMON_VARIABLES", "cifwk_url") +\
        "/generateTAFHostPropertiesJSON/?clusterId=" + str(cluster_id)
    html_response = common_functions.return_url_response(cluster_id_rest_call)
    validate_responses(html_response, "HTML")
    json_returned = common_functions.return_json_object(html_response)
    validate_responses(json_returned, "JSON Object")
    return json_returned


if __name__ == "__main__":
    config.init(__file__)
    args = parse_args()
    validate_arguments()