"""
This script is used to query the enmutils db for information

- Obtains the amount of nodes in workload pool
- Obtains the list of nodes in the workload pool
"""
# pylint: disable=F0401

import logging
import sys

import argparse
import common_functions
import config

from enmutils.lib import log
from enmutils.lib import persistence


class EnmutilsDb(object):
    """
    Provides functionality that can retrieve node information from the
    workload pool

    Queries enmutils database to retrieve specified node information
    """
    def __init__(self):
        log.log_init()
        self.enmutils_db = persistence.default_db()
        self.total_node_count = self.enmutils_db.get("total-node-count")

    def retrieve_total_node_count(self, nodes_platform_type):
        """
        Returns number of nodes in workload pool

        :param nodes_platform_type: Platform type of the nodes
        :return number of workload pool nodes
        """
        logging.info("Checking if there are nodes in workload pool...")

        workload_pool_nodes = self.retrieve_workload_pool_nodes()

        if workload_pool_nodes:
            if nodes_platform_type != "ALL":
                workload_pool_nodes = self.parse_nodes_based_on_platform_type(
                    workload_pool_nodes, nodes_platform_type)

        return len(workload_pool_nodes)

    def retrieve_total_node_count_of_ne_type(self, nodes_ne_type):
        """
        Returns number of nodes in workload pool of ne type

        :param nodes_ne_type: NE type of the nodes
        :return number of workload pool nodes
        """
        logging.info("Checking if there are nodes in workload pool...")

        workload_pool_nodes = self.retrieve_workload_pool_nodes()

        if workload_pool_nodes:
            if nodes_ne_type != "ALL":
                workload_pool_nodes = self.parse_nodes_based_on_ne_type(
                    workload_pool_nodes, nodes_ne_type)

        return len(workload_pool_nodes)

    def parse_nodes_based_on_platform_type(self, workload_pool_nodes,
                                           nodes_platform_type):
        """
        Parses nodes in the workload pool based on the platform type

        :param workload_pool_nodes: Nodes in the workload pool
        :param nodes_platform_type: Platform type of the nodes
        :return a list of workload nodes
        """
        logging.info("Parsing workload nodes of platform type: " +
                     str(nodes_platform_type))
        parsed_workload_nodes = []
        return [parsed_workload_nodes.append(workload_node)
                for workload_node in workload_pool_nodes if
                workload_node.PLATFORM_TYPE == nodes_platform_type]

    def parse_nodes_based_on_ne_type(self, workload_pool_nodes, nodes_ne_type):
        """
        Parses nodes in the workload pool based of the ne type

        :param workload_pool_nodes: Nodes in the workload pool
        :param nodes_ne_type: Ne type of the nodes
        :return a list of workload nodes of ne type
        """
        logging.info("Parsing workload nodes of ne type: " +
                     str(nodes_ne_type))
        parsed_workload_nodes = []
        return [parsed_workload_nodes.append(workload_node)
                for workload_node in workload_pool_nodes if
                workload_node.NE_TYPE == nodes_ne_type]

    def retrieve_workload_pool_nodes(self):
        """
        Returns list of nodes in the workload pool

        :return number of workload pool nodes
        """

        if self.total_node_count:
            workload_pool_nodes = self.enmutils_db.get("workload_pool").nodes
            return workload_pool_nodes

        return []

    def retrieve_active_workload_profiles(self):
        """
        :return number of active profiles

        Returns number of active profiles in workload pool
        """
        logging.info("Checking if there are active profiles in workload pool")
        active_profile_list = self.enmutils_db.get("active_workload_profiles")
        if active_profile_list is None:
            return 0
        return len(active_profile_list)


def parse_arguments():
    """
    This function parses the passed in system arguments.

    :return parser.parse_args():
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''Description: ------------ This script queries the
        enmutils db and returns back information based on the query

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -e
    ''' + sys.argv[0] + ''' --list_of_nodes
    ''' + sys.argv[0] + ''' --list_of_nodes --print_to_screen
    ''',
        epilog=''''''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-n", "--num_of_nodes",
                        help="Return amount of nodes in workload pool. "
                             "Requires a Platform type to be passed in as an "
                             "argument. Can return ALL nodes or a subset "
                             "depending on the Platform type choice.")
    parser.add_argument("-t", "--num_of_nodes_of_ne_type",
                        help="Return amount of nodes in workload pool. "
                             "Requires a ne type to be passed in as an "
                             "argument. Can return ALL nodes or a subset "
                             "depending on the ne type choice.")
    parser.add_argument("-l", "--list_of_nodes",
                        help="Return list of nodes in workload pool",
                        nargs='?', const=True)
    parser.add_argument("-a", "--num_of_active_profiles",
                        help="Return number of active workload profiles",
                        nargs='?', const=True)
    parser.add_argument("-r", "--print_to_screen",
                        help="Option to print the value to screen",
                        nargs='?', const=True)

    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def execute_operation(args):
    """
    Executes the functions in the ENM Utils Operator class based on the
    operation specified.

    :param args: Argument list passed into the script
    """

    enmutils_db = EnmutilsDb()

    if args.num_of_nodes:
        logging.info("Returning number of nodes in workload pool")
        nodes_platform_type = args.num_of_nodes
        number_of_nodes = enmutils_db.\
            retrieve_total_node_count(nodes_platform_type)

        logging.info("Number of nodes: " + str(number_of_nodes))

        common_functions.print_to_screen(str(number_of_nodes),
                                         args.print_to_screen)

    if args.num_of_nodes_of_ne_type:
        logging.info("Returning number of nodes of ne type in workload pool")
        nodes_ne_type = args.num_of_nodes_of_ne_type
        number_of_nodes_of_ne_type = enmutils_db.\
            retrieve_total_node_count_of_ne_type(nodes_ne_type)

        logging.info("Number of nodes of ne type: " +
                     str(number_of_nodes_of_ne_type))

        common_functions.print_to_screen(str(number_of_nodes_of_ne_type),
                                         args.print_to_screen)

    if args.list_of_nodes:
        logging.info("Returning list of nodes in workload pool")

        workload_pool_nodes = enmutils_db.retrieve_workload_pool_nodes()

        common_functions.print_to_screen(workload_pool_nodes,
                                         args.print_to_screen)

    if args.num_of_active_profiles:
        logging.info("Returning number of active workload profiles")

        active_workload_profiles = \
            enmutils_db.retrieve_active_workload_profiles()

        common_functions.print_to_screen(active_workload_profiles,
                                         args.print_to_screen)


if __name__ == "__main__":
    config.init(__file__)
    arguments = parse_arguments()
    execute_operation(arguments)