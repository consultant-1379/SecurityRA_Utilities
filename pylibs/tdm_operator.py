"""
This script allows to retrieve the required information from TDM data source.
"""
import logging
import sys
import common_functions
import argparse
import config
import configuration

CONFIG = configuration.UtilsConfig()
TDM_BASE_URL = CONFIG.get("COMMON_VARIABLES", "tdm_base_url")


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    This script is used to retrieve the node names from TDM central nodes
    data source.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -n rfa250 -d 17.9
      -> ''' + sys.argv[0] + ''' --nodes_to_retrieve rfa250 -d 17.10
      --file_to_write "../../libraries/workload_configuration
      /separate_node_pool.txt" -v
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-c", "--context",
                        help="context name to find the respective TDM data "
                             "source, Example: RFA250", required=True)
    parser.add_argument("-s", "--data_source",
                        help="data source name available under given context"
                             "from data need to be retrieved,"
                             "example: Nodes_to_Add, which will provide the "
                             "RFA250 nodes to add data source under RFA250 "
                             "context, earlier known as central CSV",
                        required=True)
    parser.add_argument("-d", "--drop",
                        help="drop version to find the respective TDM data "
                             "source", required=True)
    parser.add_argument("-n", "--nodes_to_retrieve",
                        help="Nodes to retrieve from TDM central nodes, "
                             "Only values mentioned in choices are supported",
                        choices=["rfa250", "prepopulated_node",
                                 "rfa250_non_prepopulated_node"],
                        required=True)
    parser.add_argument("-f", "--file_to_write",
                        help="Full path of the file to write the output")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        parser.exit()
    return parser.parse_args()


def return_context_id(context):
    """
    :param context:
    :return context_id:
    This function is used to get the context id for given context
    """
    context_id_url = TDM_BASE_URL + "/api/contexts?name=" + context
    logging.debug("Fetching context id for given context using " +
                  context_id_url)
    json_object = common_functions.return_json_object(
        common_functions.return_url_response(context_id_url))
    logging.info("Returning context id for " + context + " is " +
                 json_object["id"])
    return json_object["id"]


def return_approved_data_source_id(context_id, drop, data_source):
    """
    :param context_id:
    :param drop:
    :param data_source:
    :return data_source_id:
    This function is used to get data_source_id of given data source
    for given context id and drop
    """
    data_source_id_url = \
        TDM_BASE_URL + "/api/datasources/latest?context=" + context_id + \
        "&name=" + data_source + "_" + drop + "&approved=true"
    logging.debug("Fetching data source id for given context id using " +
                  data_source_id_url)
    json_object = common_functions.return_json_object(
        common_functions.return_url_response(data_source_id_url))
    logging.info("Returning data source id for " + context_id + " is " +
                 json_object["id"])
    return json_object["id"]


def return_tdm_url(drop, context, ds_name):
    """
    :param drop:
    :param context:
    :param ds_name:
    :return tdm_url:
    This function is used to get the tdm rest api url for given context,
    data source name and drop
    """
    context_id = return_context_id(context)
    data_source_id = return_approved_data_source_id(context_id, drop, ds_name)
    tdm_url = TDM_BASE_URL + "/api/datasources/" + data_source_id + "/records"
    logging.info("Returning tdm_url " + tdm_url)
    return tdm_url


def return_node_names_list(json_object, search_key, search_value):
    """
    :param json_object:
    :param search_key:
    :param search_value:
    :return node_names_list:
    This function loops through the parsed JSON string
    and returns the required expected_value_list.
    """
    node_names_list = []
    for record in json_object:
        if record["values"][search_key] == search_value:
            node_names_list.append(record["values"]["networkElementId"])
    return node_names_list


def return_rfa250_non_prepop_nodes(rfa250_nodes, prepop_nodes):
    """
    :param rfa250_nodes:
    :param prepop_nodes:
    :return rfa250_non_prepopulated_nodes:
    This function retrieve the list of RFA250 non prepopulated nodes from
    central nodes data source in TDM and returns the list of node names.
    """
    return [rfa250_node for rfa250_node in rfa250_nodes if rfa250_node not
            in prepop_nodes]


def write_data_from_list_to_file(nodes_data, file_to_write):
    """
    :param nodes_data:
    :param file_to_write: will write the data from list to a file.
    """
    logging.info("Writing node names into file " + file_to_write)
    opened_file = open(file_to_write, 'w')
    for data in nodes_data:
        opened_file.write("%s\n" % data)
    opened_file.close()


def retrieve_nodes():
    """
    :return nodes_list:
    This function will retrieve the nodes list with respective to given
    drop, context, data source from tdm
    """
    nodes_list = []
    returned_url = return_tdm_url(args.drop, args.context, args.data_source)
    html_response = common_functions.return_url_response(returned_url)
    json_returned = common_functions.return_json_object(html_response)
    logging.debug(
            "Retrieving the node names related to " + args.nodes_to_retrieve +
            " from TDM central nodes data source " + args.data_source +
            " belongs to context " + args.context + " and drop " + args.drop)
    if args.nodes_to_retrieve is "rfa250":
        nodes_list = return_node_names_list(json_returned, "RFA250", "y")
    elif args.nodes_to_retrieve is "prepopulated_node":
        nodes_list = return_node_names_list(json_returned,
                                            "prepopulatedNode", "y")
    elif args.nodes_to_retrieve is "rfa250_non_prepopulated_node":
        rfa250_list = return_node_names_list(json_returned, "RFA250", "y")
        prepop_list = return_node_names_list(json_returned,
                                             "prepopulatedNode", "y")
        nodes_list = return_rfa250_non_prepop_nodes(rfa250_list, prepop_list)

    logging.debug("Writing output to screen")
    for node in nodes_list:
        print node

    if args.file_to_write:
        logging.debug("Writing output to " + args.file_to_write)
        write_data_from_list_to_file(nodes_list, args.file_to_write)

    return nodes_list


if __name__ == "__main__":
    config.init(__file__)
    args = parse_args()
    common_functions.determine_logging_level(args.verbose)
    retrieve_nodes()