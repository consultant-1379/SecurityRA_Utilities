"""
This script allows for common functionality within the repo
"""

import json
import logging
import socket
import sys
import urllib2
import os
import fnmatch
import subprocess
import shlex
import paramiko

import configuration
import config


CONFIG = configuration.UtilsConfig()


def return_url_response(url):
    """
    :param url:
    :return HTML response: Output of the URL
    """
    fail_flag = False
    proxy_servers = ['https', 'http']
    logging.info("Returning URL response from the URL: " + str(url))
    for proxy_type in sorted(proxy_servers, reverse=True):
        try:
            logging.\
                info("Attempting to use " + str(proxy_type) + "Proxy: " +
                     str(CONFIG.get("COMMON_VARIABLES",
                                    "proxy_server_hostname")))
            proxy = urllib2.ProxyHandler({
                proxy_type:
                    CONFIG.get("COMMON_VARIABLES", "proxy_server_hostname")
            })
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
            response = urllib2.urlopen(url, timeout=180.0)
        except urllib2.HTTPError, error:
            logging.warning("HTTP error. Error Code: " + str(error.code))
            fail_flag = True
            continue
        except urllib2.URLError, error:
            logging.warning(
                "URL Error. Might have timed out (60 second timeout).")
            logging.warning("URL/Proxy Error. Error Code: " + str(error.args))
            fail_flag = True
            continue
        except ValueError, response:
            logging.warning("Invalid URL detected. Please pass in a valid URL")
            logging.warning(response)
            fail_flag = True
            continue
        except socket.error as err:
            logging.warning("Socket timeout error")
            logging.warning(err)
            fail_flag = True
            continue
        fail_flag = False
        break

    if fail_flag:
        sys.exit(1)
    logging.debug(url)
    html_response = response.read()
    return html_response


def return_json_object(html_response):
    """
    :param html_response:
    :return parsed_json: a json object from the HTML Response
    """
    logging.info("Returning JSON from HTML response...")
    try:
        parsed_json = json.loads(html_response)
    except ValueError:
        logging.error("Invalid JSON Object")
        logging.error("HTML Response: ")
        logging.error(str(html_response))
        return False
    return parsed_json


def get_json_data_from_file(conf_file):
    """
    :param conf_file: JSON file to read in the data
    Load JSON object from the config file
    :return: JSON Object
    """
    with open(conf_file) as json_data:
        json_returned = json.load(json_data)
        logging.debug("JSON: " + str(json_returned))
        return json_returned


def ssh_run_command(**kwargs):
    """
    :return returned_value:
    This function is used to make the SSH connection to the
    deployment in question, and returns the return_value based
    on the command passed into the function.
    """
    server_ip = kwargs.pop('server_ip')
    username = kwargs.pop('username')
    password = kwargs.pop('password')
    command = kwargs.pop('command')
    if kwargs:
        raise TypeError('Unexpected **kwargs: %r' % kwargs)
    logging.info("SSH connect using IP " + str(server_ip))
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, username=username, password=password)
    except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
            paramiko.SSHException, socket.error) as exception:
        logging.error(
            "Could not connect to IP " + str(server_ip) + ". Exiting.")
        logging.error("See output of error: " + str(exception))
        sys.exit(1)
    logging.info("Executing command: " + str(command))
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status is not 0:
        logging.error("Command has exited with exit code " + str(exit_status))
        returned_value = stdout.readlines()
        for line in stderr.readlines():
            logging.error(line)
        for line in returned_value:
            logging.info(line)
        sys.exit(1)
    try:
        returned_value = stdout.readlines()
        for line in returned_value:
            logging.info(line)
    except IndexError as exception:
        logging.error("No value found, see output of error: " + str(exception))
        returned_value = ""
    ssh.close()
    return returned_value


def print_to_screen(item_to_print, output_to_screen):
    """
    :param item_to_print: item to print to console
    :param output_to_screen: flag to check whether to print or not
    If output_to_screen is present it will print the item to the console/screen
    """
    if output_to_screen:
        print item_to_print


def search_for_iso_version(json_returned, artifact_id):
    """
    :param json_returned:
    :param artifact_id:
    :return iso_version:
    This function loops through the parsed JSON string
    and returns the required iso_version.
    """
    if isinstance(json_returned, dict):
        for key_found in json_returned:
            if key_found == "artifactName":
                if json_returned[key_found] == artifact_id:
                    return json_returned["version"]
            iso_version = search_for_iso_version(json_returned[key_found],
                                                 artifact_id)
            if iso_version:
                return iso_version
    elif isinstance(json_returned, list):
        for item in json_returned:
            if isinstance(item, (list, dict)):
                iso_version = search_for_iso_version(item, artifact_id)
                if iso_version:
                    return iso_version


def write_to_build_properties_file(build_properties_path, variable_to_write):
    """
    Writes to a build properties file
    :param build_properties_path: File path for the properties file values are
     written
    :param variable_to_write: Value to write to the properties file
    """
    with open(build_properties_path, "a") as build_properties_file:
        build_properties_file.write(variable_to_write)


def determine_logging_level(verbose_argument):
    """
    :param verbose_argument: Argument to determine if verbose is enabled
    Enables debug Logging
    """
    if verbose_argument:
        config.console.setLevel(logging.DEBUG)
        logging.debug("Logging Level set to DEBUG")
    else:
        config.console.setLevel(logging.INFO)
        logging.info("Logging Level set to INFO")


def get_utils_base_directory():
    """
    :return: Return the utils base directory.
    """
    script_directory = os.path.dirname(os.path.realpath(__file__))
    logging.debug("Current directory is: " + str(script_directory))
    parent_directory = \
        os.path.abspath(os.path.join(script_directory, os.pardir))
    utils_base_directory = \
        os.path.abspath(os.path.join(parent_directory, os.pardir))
    logging.debug("Utils base directory is: " + str(utils_base_directory))
    return utils_base_directory


def find_file(file_name_to_find):
    """
    :param file_name_to_find: Name of file to find in utils base directory
    :return: File path
    """
    base_dir = get_utils_base_directory()
    logging.info("Searching for " + file_name_to_find + " in " + base_dir)
    for root, directory_names, file_names in os.walk(base_dir):
        logging.debug(str(directory_names))
        for filename in fnmatch.filter(file_names, file_name_to_find):
            file_found = os.path.join(root, filename)
            logging.info(file_found + " has been found")
            return file_found

    logging.error("Unable to find file")
    sys.exit(1)


def sftp_file(**kwargs):
    """
    SFTP a file to a given destination.

    This function can ftp a local file to a remote server
    via sftp, with the given username and password
    """
    ip_address = kwargs.pop('ip_address')
    username = kwargs.pop('username')
    password = kwargs.pop('password')
    local_file_path = kwargs.pop('local_file_path')
    remote_file_path = kwargs.pop('remote_file_path')
    private_key = kwargs.pop('private_key')
    deployment_type = kwargs.pop('deployment_type')
    set_file_permissions = kwargs.pop('set_file_permissions')
    sftp_command = kwargs.pop("sftp_command")
    if kwargs:
        raise TypeError('Unexpected **kwargs: %r' % kwargs)

    transport = paramiko.Transport((ip_address, 22))
    if deployment_type == "cloud":
        transport.connect(username=username, pkey=private_key)
    elif deployment_type == "physical":
        transport.connect(username=username, password=password)
    else:
        logging.error("Unknown Deployment Type")
        sys.exit(1)
    logging.debug(local_file_path)
    logging.debug(remote_file_path)
    sftp = paramiko.SFTPClient.from_transport(transport)
    if sftp_command == "put":
        sftp.put(local_file_path, remote_file_path)
    elif sftp_command == "get":
        sftp.get(remote_file_path, local_file_path)
    elif sftp_command == "put_all":
        os.chdir(os.path.split(local_file_path)[0])
        parent = os.path.split(local_file_path)[1]
        for directory in os.walk(parent):
            directory_to_create = os.path.join(remote_file_path, directory[0])
            try:
                sftp.mkdir(directory_to_create)
            except IOError, exception:
                logging.warning(directory_to_create +
                                " already exists or something has "
                                "gone wrong.")
                logging.warning(str(exception))
                break
            for file_to_copy in directory[2]:
                sftp.put(os.path.join(directory[0], file_to_copy),
                         os.path.join(remote_file_path, directory[0],
                                      file_to_copy))
    else:
        logging.error("Unknown SFTP command: " + sftp_command)
        sys.exit(1)
    if set_file_permissions:
        set_remote_file_permissions(sftp, remote_file_path,
                                    set_file_permissions)
    sftp.close()
    transport.close()


def set_remote_file_permissions(sftp_client, remote_file_path, mode):
    """
    :param sftp_client: SFTP Client object
    :param remote_file_path: Location of the file on the remote server
    :param mode: The permissions to be set on the remote file

    Sets the file permissions for a file on a remote server
    """
    logging.info("Setting File permissions on Remote File to " + oct(mode))
    logging.debug("Remote File = " + remote_file_path)
    sftp_client.chmod(remote_file_path, mode)


def get_ssh_client_for_physical(host_ip, username, password):
    """
    :param host_ip: IP of Host to connect to
    :param username:
    :param password:
    :return Creates SSH connection to the host and returns SSH client
    """
    try:
        logging.info("Setting Up SSH Connection to " + host_ip)
        ssh = paramiko.SSHClient()
        logging.debug("Client Created")
        logging.debug("Set policy to connect to vm without known host key")
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.debug("Username = " + username)
        logging.debug("Password = " + password)
        ssh.connect(host_ip, username=username, password=password)
    except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
            paramiko.SSHException, socket.error) as exception:
        logging.error("Unable to connect to " + host_ip)
        logging.error(str(exception))
        sys.exit(1)
    return ssh


def get_directory_setup_command(action):
    """
    :param action: Action for directory setup (create/remove)
    :return: Command to setup the directory
    """
    if action is "create":
        command = "mkdir -p"
    elif action is "remove":
        command = "rm -rf"
    else:
        logging.error("Unknown action " + action)
        logging.error("Must select create or remove")
        sys.exit(1)
    return command


def run_cli_command(command):
    """
    :param command: cli command to run
    :return: dictionary containing two keys,
        the standard_error, and standard_output strings
    :raise: SystemExit if the return code of the cli command is non zero

    Run the given cli command and return the result.
    """
    logging.info("Running cli command (" + command + ")")
    try:
        process = subprocess.Popen(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        process_standard_output, process_standard_error = process.communicate()
    except OSError as error:
        logging.error("Something went wrong running the command."
                      " Please Investigate")
        logging.error(error.strerror)
        sys.exit(1)
    if process.returncode != 0:
        logging.error(
            'The command failed with exit code ' + str(process.returncode) +
            '. Heres the output: ' + process_standard_output +
            '\nError: ' + process_standard_error
        )
        sys.exit(process.returncode)
    logging.debug(process_standard_output)
    logging.debug(process_standard_error)
    logging.info("cli command completed")
    return {
        'standard_output': process_standard_output,
        'standard_error': process_standard_error
    }


def get_command_output(command_output):
    """
    :param command_output: stdout of a command ran on the VM

    Logs the command output
    """
    if not command_output:
        logging.debug("No output for the command")
    else:
        logging.info("Output for Command")
        for output in command_output:
            logging.info(output.encode('utf-8').strip())
        logging.info("End of Command Output")