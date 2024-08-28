"""
This is a client to fetch the information from ddp.py
"""
import logging
import sys
import argparse

from MTELoopScripts.etc.pylibs.lib.deployment.cloud import CloudDeployment
from MTELoopScripts.etc.pylibs import config
from MTELoopScripts.etc.pylibs import common_functions


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
    python modules in ddp.py
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -d ieatenmpca05 --hostname
         ''' + sys.argv[0] + ''' -d ieatenmpca05 --port
         ''' + sys.argv[0] + ''' -d ieatenmpca05 --cron

    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-d", "--deployment_name",
                        help="takes the deployment name as input for which the"
                             "ddp information is to be fetched",
                        required=True)
    parser.add_argument("-n", "--hostname",
                        help="returns the ddp hostname for the given "
                             "deployment", nargs='?', const=True)
    parser.add_argument("-p", "--port",
                        help="returns the ddp port number for the given "
                             "deployment", nargs='?', const=True)
    parser.add_argument("-c", "--cron",
                        help="returns the ddp cron for the given deployment",
                        nargs='?', const=True)

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def execute_script_functions(args):
    """
    :param args: Argument list returned by arg parser
    Executes the functions in the script
    """
    common_functions.determine_logging_level(args.verbose)

    cloud_deployment = CloudDeployment(args.deployment_name)
    ddp = cloud_deployment.ddp

    if args.hostname:
        print ddp.hostname

    if args.cron:
        print ddp.cron

    if args.port:
        print ddp.port


if __name__ == "__main__":
    config.init(__file__)
    execute_script_functions(parse_args())