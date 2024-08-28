"""
This module is used to carry out type
conversion between JSON and YAML formats
"""

import ast
import json
import logging
import sys
import yaml

from os import path


class JsonYamlConverter(object):
    """
    This class carries out type conversion between JSON and YAML formats

    """

    @staticmethod
    def json_to_yaml(json_content, file_name):
        """
        Converts JSON into YAML format

        :param json_content:
        :param file_name:
        """
        try:
            logging.info("Converting from JSON to YAML...")
            JsonYamlConverter.write_to_file(yaml.dump(ast.literal_eval(json_content),
                                                      default_flow_style=False), ".yaml", file_name)
        except (ValueError, TypeError, AttributeError) as error:
            logging.error(str(error))
            sys.exit(1)

    @staticmethod
    def yaml_to_json(yaml_content, file_name):
        """
        Converts YAML into JSON format

        :param yaml_content:
        :param file_name:
        """
        try:
            logging.info("Converting from YAML to JSON...")
            converted_json = json.dumps(yaml.load(yaml_content),
                                        sort_keys=True)
            JsonYamlConverter.write_to_file(converted_json, ".json", file_name)
            return converted_json
        except (ValueError, TypeError, AttributeError) as error:
            logging.error(str(error))
            sys.exit(1)

    @staticmethod
    def write_to_file(content_to_write_to_file, file_type, file_name):
        """
        Write newly formatted data to file

        :param content_to_write_to_file:
        :param file_type:
        :param file_name:
        """
        with open(file_name + file_type, 'a') as file_to_write:
            file_to_write.write(content_to_write_to_file)

    @staticmethod
    def read_file_for_content_parsing(file_for_conversion):
        """
        Read file in preparation for JSON/YAML parsing

        :param file_for_conversion:
        :return:
        """
        with file(file_for_conversion) as file_to_read:
            return file_to_read.read()