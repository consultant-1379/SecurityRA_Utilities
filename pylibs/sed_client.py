"""
This is a client to fetch information from the sed
"""
import logging
import sys
import argparse

from MTELoopScripts.etc.pylibs.lib.deployment.cloud import CloudDeployment
from MTELoopScripts.etc.pylibs import config
from MTELoopScripts.etc.pylibs import common_functions


def create_parser():
    """This function creates a parses for the arguments for this client.
    :return parser
    """
    arg_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    This script is used to create a client between a script and access sed.py
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -d ieatenmpca05 -p httpd_fqdn

    '''
    )
    arg_parser.add_argument("-v", "--verbose",
                            help="increase output verbosity",
                            action="store_true")
    arg_parser.add_argument("-d", "--deployment_name",
                            help="takes the deployment name as input for "
                                 "which the sed is to be fetched",
                            required=True)
    arg_parser.add_argument("-p", "--sed_parameter",
                            help="The parameter to return from the sed",
                            required=True)

    return arg_parser


def evaluate_args(arg_parser):
    """Evaluate args are passed in"""
    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        arg_parser.print_help()
        sys.exit(1)


def execute_script_functions(args):
    """
    :param args: Argument list returned by arg parser
    Executes the functions in the script
    """
    common_functions.determine_logging_level(args.verbose)

    sed = CloudDeployment(args.deployment_name).sed

    if args.sed_parameter == "httpd_fqdn":
        print sed.httpd_fqdn


if __name__ == "__main__":
    config.init(__file__)
    parser = create_parser()
    evaluate_args(parser)
    execute_script_functions(parser.parse_args())