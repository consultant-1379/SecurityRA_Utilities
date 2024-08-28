"""
This is used as a client to enm_iso.py
"""

import logging
import sys

# disable=relative-import
import MTELoopScripts.etc.pylibs.argparse
import MTELoopScripts.etc.pylibs.common_functions
import MTELoopScripts.etc.pylibs.config

from enm_iso import ENMISO


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = MTELoopScripts.etc.pylibs.argparse.ArgumentParser(
        formatter_class=MTELoopScripts.etc.pylibs.argparse.
        RawDescriptionHelpFormatter,
        description='''
    Description:
    This script is used to create a client between a script and the
    python modules in enm_iso.py.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -iv 1.58.19 -f 'version' -n
      ERICddccore_CXP9035927
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="iIncrease output verbosity",
                        action="store_true")
    parser.add_argument("-iv", "--iso_version",
                        help="Version of the ISO to query",
                        required=True)
    parser.add_argument("-f", "--iso_field",
                        help="Field from ISO to be returned")
    parser.add_argument("-n", "--package_name",
                        help="Field from ISO to be returned")

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
    MTELoopScripts.etc.pylibs.common_functions.determine_logging_level(
        args.verbose)

    iso = ENMISO(args.iso_version)

    if args.iso_field:
        iso_content_value = iso.parse_iso_content_for_field(
            args.package_name, args.iso_field)
        print iso_content_value


if __name__ == "__main__":
    MTELoopScripts.etc.pylibs.config.init(__file__)
    execute_functions(parse_args())