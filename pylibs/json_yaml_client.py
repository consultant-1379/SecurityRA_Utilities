"""
This is used as a client to json_yaml_converter.py
"""

import logging
import sys

import argparse
import common_functions
import config

from json_yaml_converter import JsonYamlConverter


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
    python modules in json_yaml_converter.py.

    It carries out type conversion between JSON and YAML formats.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -j -f <FILE_PATH>
      -> ''' + sys.argv[0] + ''' -y -f <FILE_PATH> -n <NAME_OF_NEWLY_CREATED_FILE>
      -> ''' + sys.argv[0] + ''' -y -d <JSON_VARIABLE>
    '''
    )
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-j", "--yaml_to_json",
                        help="Converts YAML to JSON", action="store_true")
    parser.add_argument("-y", "--json_to_yaml",
                        help="Converts JSON to YAML", action="store_true")
    group.add_argument("-f", "--file",
                       help="File you wish to convert")
    group.add_argument("-d", "--data",
                       help="Data you wish to convert")
    parser.add_argument("-n", "--name",
                        help="The name you wish to call your newly created file. "
                             "Defaults to temp otherwise", nargs='?', default="temp")
    parser.add_argument("-o", "--output_to_screen",
                        help="Prints content to screen. Note that "
                             "this is only supported for JSON output",
                        action="store_true")

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

    if args.name:
        file_name = args.name

    if args.data:
        content_to_convert = args.data

    if args.file:
        content_to_convert = JsonYamlConverter.read_file_for_content_parsing(args.file)

    if args.yaml_to_json:
        converted_json = JsonYamlConverter.yaml_to_json(content_to_convert, file_name)

        if args.output_to_screen:
            print converted_json

    if args.json_to_yaml:
        JsonYamlConverter.json_to_yaml(content_to_convert, file_name)

if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())