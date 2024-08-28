"""
This script is used to connect to a VM in a ENM cloud deployment.

- Handles the creation of PEM Key on the gateway to connect to a VM.
- Functionality to copy the PEM Key to a VM
- Functionality to run commands on a VM from gateway
"""

import json
import logging
import os
import socket
import stat
import sys
import paramiko

import argparse
import common_functions
import config
import emt_deployment_client
import retrieve_maintrack_openstack_deployment_details
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
    This script is used to connect to a VM in a ENM cloud deployment.
    - Handles the creation of PEM Key on the gateway to connect to a VM.
    - Functionality to copy the PEM Key to a VM
    - Functionality to run commands on a VM from gateway
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -c ieatenmpca08 -n esmon -t external -i ipv4
      -> ''' + sys.argv[0] + ''' -c ieatenmpca08 -n esmon -t external -i ipv4
       --copy_pem_to_vm
      -> ''' + sys.argv[0] + ''' -c ieatenmpca08 -n esmon -t external -i ipv4
       --run_command "whoami"
      -> ''' + sys.argv[0] + ''' -c ieatenmpca08 -n elementmanager -t
       internal -i ipv4 -r "ls -lart /var/tmp"
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-c", "--cluster_id",
                        help="Cluster ID of the deployment being used",
                        required=True)
    parser.add_argument("-n", "--vm_name",
                        help="Service name of VM we are connecting to",
                        required=True)
    parser.add_argument("-t", "--type_of_connection",
                        help="Whether VM is internal or external",
                        required=True,
                        choices=['internal', 'external'])
    parser.add_argument("-i", "--ip_version",
                        help="Specify the IP type to retrieve from the SED",
                        required=True,
                        choices=['ipv4', 'ipv6'])
    parser.add_argument("-p", "--copy_pem_to_vm",
                        help="Optional Flag to copy the PEM key"
                             " to the specified VM", nargs='?', const=True)
    parser.add_argument("-r", "--run_command",
                        help="Optional Flag to run command on VM over ssh. "
                             "Specify the command here")
    parser.add_argument("-o", "--output_to_screen",
                        help="Option to output the value of run command"
                             " to screen", nargs='?', const=True)

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def parse_stack_information(stack_details, key_to_search):
    """

    :param stack_details: Detailed information from the openstack stack command
    :param key_to_search: Key to search for in the stack details
    :return: Value for the key_to_search
    :raise SystemExit if key is not found
    """

    for detail in stack_details:
        logging.debug(str(detail))
        if detail == key_to_search:
            logging.debug(str(stack_details[detail]))
            return stack_details[detail]

    logging.error("Unable to find " + key_to_search + " in stack details")
    sys.exit(1)


def check_stack_status(stack_information):
    """
    :param stack_information: Stack information returned from the CLI command
    :raise SystemExit if the Stack status is not CREATE_COMPLETE
    """

    stack_status = parse_stack_information(stack_information, "stack_status")
    logging.info("Stack Status = " + stack_status)
    if stack_status != "CREATE_COMPLETE":
        logging.error("There is an issue with the stack. Please Investigate")
        sys.exit(1)


def create_pem_key_directory(base_dir):
    """
    :param base_dir: Base Directory of the script
    :return:  The directory the pem key is created in

    Creates a directory on the gateway to store the pem key
    """
    pem_key_directory = base_dir + "/pem_keys"
    if os.path.exists(pem_key_directory):
        logging.info("PEM Key Directory Exists")
    else:
        logging.info("Create Directory to store PEM Keys")
        os.makedirs(pem_key_directory)
        logging.info("PEM Key Directory created: " + str(pem_key_directory))

    return pem_key_directory


def create_local_pem_key_file(cluster_id, pem_key_value, pem_key_location):
    """
    :param cluster_id: Cluster ID of deployment
    :param pem_key_value: Key to write to PEM File
    :param pem_key_location: Path/Location on the gateway to create the pem key
    :return pem_file_name: File name containing the PEM Key

    This function writes the PEM Key value to a file
    """

    pem_file_name = pem_key_location + "/" + cluster_id + ".pem"

    logging.debug("Writing to pem key file: " + pem_file_name)
    pem_file_to_write_to_gateway = open(pem_file_name, 'w')
    pem_file_to_write_to_gateway.write(pem_key_value)
    pem_file_to_write_to_gateway.close()
    logging.info("Pem Key File successfully stored on gateway")
    set_pem_file_permission(pem_file_name)
    return pem_file_name


def set_pem_file_permission(file_name):
    """
    :param file_name: Name of PEM File

    Sets the file permissions to 0600
    """
    logging.info("Changing File Permissions on " + file_name)
    os.chmod(file_name, stat.S_IRUSR | stat.S_IWUSR)
    logging.info("File Permission on " + file_name + ": " +
                 str(oct(stat.S_IMODE(os.lstat(file_name).st_mode))))


def get_ssh_client(vm_ip, pem_key):
    """
    :param vm_ip: IP of VM
    :param pem_key: PEM Key
    :return Creates SSH connection to the VM and returns SSH client
    """
    try:
        logging.info("Setting Up SSH Connection to " + vm_ip)
        ssh = paramiko.SSHClient()
        logging.debug("Client Created")
        logging.debug("Set policy to connect to vm without known host key")
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.info("Creating Private Key Object from pem file")
        private_pem_key = paramiko.RSAKey.from_private_key_file(pem_key)
        username = CONFIG.get("MT_Cloud", "cloud_vm_username")
        logging.debug("Cloud VM Username = " + username)
        ssh.connect(vm_ip, username=username, pkey=private_pem_key)
    except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
            paramiko.SSHException, socket.error) as exception:
        logging.error("Unable to connect to " + vm_ip)
        logging.error(str(exception))
        sys.exit(1)
    return ssh


def run_command_on_vm_host(vm_ip, pem_key, command):
    """
    :param vm_ip: IP of the VM to run the command on
    :param pem_key: Location of the PEM key
    :param command: Command to run on the VM

    Runs the command passed in on the VM
    """
    logging.info("Running the following command on " + vm_ip)
    logging.info(command)
    try:
        ssh_client = get_ssh_client(vm_ip, pem_key)
    except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
            paramiko.SSHException, socket.error) as exception:
        logging.warning("Could not connect to " + str(vm_ip))
        logging.warning("See output of error: " + str(exception))
        sys.exit(1)

    stdin, stdout, stderr = ssh_client.exec_command(command, get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status is not 0:
        logging.error("Command has exited with exit code " + str(exit_status))
        returned_value = stdout.readlines()
        logging.error(str(returned_value))
        sys.exit(1)
    try:
        returned_value = stdout.readlines()
        common_functions.get_command_output(returned_value)
        ssh_client.close()
        return returned_value
    except IndexError as exception:
        logging.error("No value found, see output of error: " + str(exception))
        ssh_client.close()


def copy_pem_file_to_vm(vm_name, vm_ip, pem_key_path, pem_key_name):
    """
    :param vm_name: Name of the VM
    :param vm_ip: IP of the VM
    :param pem_key_name: PEM Key Name
    :param pem_key_path: PEM Key file full path

    This function copies the pem key to the specified VM
    """
    logging.info("Copying " + pem_key_path + " to " + vm_name)
    remote_pem_key_location = "/var/tmp/pem_key"
    command = "mkdir -p " + remote_pem_key_location
    # Create remote path to store PEM Key
    run_command_on_vm_host(vm_ip, pem_key_path, command)
    private_pem_key = paramiko.RSAKey.from_private_key_file(pem_key_path)
    common_functions.sftp_file(
        ip_address=vm_ip, username=CONFIG.get("MT_Cloud", "cloud_vm_username"),
        local_file_path=pem_key_path,
        remote_file_path=remote_pem_key_location + "/" + pem_key_name,
        deployment_type="cloud", password=None, private_key=private_pem_key,
        set_file_permissions=stat.S_IRUSR | stat.S_IWUSR, sftp_command="put")
    if vm_name == "for_services_vm":
        run_command_on_vm_host(vm_ip, pem_key_path,
                               "sudo cp " + remote_pem_key_location + "/" +
                               pem_key_name + " /vnflcm-ext")
        run_command_on_vm_host(vm_ip, pem_key_path,
                               "sudo chown " +
                               CONFIG.get("MT_Cloud", "cloud_vm_username") +
                               ":" +
                               CONFIG.get("MT_Cloud", "cloud_vm_username") +
                               " /vnflcm-ext/" + pem_key_name)
        remote_pem_key_location = "/vnflcm-ext"
    logging.info("Pem key file is available in " + vm_name + " at " +
                 remote_pem_key_location + "/" + pem_key_name)


def get_deployment_details(cluster_id):
    """
    :param cluster_id: Cluster ID of the deployment

    Gets the deployment information from the
    maintrack_openstack_deployment_json file

    :return: os_project_name, os_username, os_password, os_auth_url, openstack_version
    """
    logging.info("Getting Deployment Details from DIT")
    dit = retrieve_maintrack_openstack_deployment_details. \
        RetrieveFromDIT(cluster_id)
    os_project_name = dit.get_project_content("name")
    os_username = dit.get_project_content("username")
    os_password = dit.get_project_content("password")
    os_auth_url = dit.get_pod_content("authUrl")
    openstack_version = \
        emt_deployment_client.get_deployment_property(cluster_id, 'openstack_version')

    logging.debug("\t" + os_auth_url + "\n\t" + os_username + "\n\t" +
                  os_password + "\n\t" + os_project_name)
    return os_project_name, os_username, os_password, os_auth_url, openstack_version


def setup_openstack_env_variables(os_project_name, os_username, os_password,
                                  os_auth_url):
    """
    :param os_project_name:
    :param os_username:
    :param os_password:
    :param os_auth_url:

    This function sets the required openstack environment variables
    that are necessary for running openstack cli commands
    """
    logging.info("Setting up openstack environment variables")
    os.environ["OS_AUTH_URL"] = os_auth_url
    os.environ["OS_PROJECT_NAME"] = os_project_name
    os.environ["OS_USERNAME"] = os_username
    os.environ["OS_PASSWORD"] = os_password


def create_env_setup_script(**kwargs):
    """
    :raise TypeError: When unexpected argument is passed in

    Creates a env_setup script that sets the required openstack environment
    variables that are necessary for running openstack cli commands
    """
    cluster_id = kwargs.pop('cluster_id')
    os_project_name = kwargs.pop('os_project_name')
    os_username = kwargs.pop('os_username')
    os_password = kwargs.pop('os_password')
    os_auth_url = kwargs.pop('os_auth_url')
    openstack_version = kwargs.pop('openstack_version')
    setup_file_location = kwargs.pop('setup_file_location')

    if kwargs:
        raise TypeError('Unexpected **kwargs: %r' % kwargs)

    logging.info("Creating script to source the deployment details ")
    env_setup_name = setup_file_location + "/" + cluster_id + "_" + \
        os_project_name + ".sh"

    logging.info("Creating script: " + env_setup_name)
    env_setup_script = open(env_setup_name, 'w')
    env_setup_script.write("export OS_PROJECT_NAME='" + os_project_name +
                           "'\n")
    env_setup_script.write("export OS_USERNAME='" + os_username + "'\n")
    env_setup_script.write("export OS_PASSWORD='" + os_password + "'\n")
    env_setup_script.write("export OS_AUTH_URL='" + os_auth_url + "'\n")
    if openstack_version:
        if openstack_version.lower() not in ["mitaka", "newton"]:
            env_setup_script.write("export OS_USER_DOMAIN_NAME='Default'\n")
            env_setup_script.write("export OS_PROJECT_DOMAIN_ID='default'\n")
            env_setup_script.write("export OS_INTERFACE='public'\n")
            env_setup_script.write("export OS_IDENTITY_API_VERSION=3\n")
    env_setup_script.close()
    logging.info("Credential Script Created: " + env_setup_name)


def get_sed_params(deployment_name, sed_param, sed_param_connection_type,
                   sed_param_ip_version):
    """
    :param deployment_name: Name of the deployment
    :param sed_param: Name of the VM
    :param sed_param_connection_type: internal or external
    :param sed_param_ip_version: ipv4 or ipv6
    :raise SystemExit if the details of the vm are empty
    :return: The IP of the sed parameter

    This function is used to get the IP for a server
    """
    logging.info("Retrieving the " + sed_param_connection_type + " " +
                 sed_param_ip_version + " address for " + sed_param)
    dit = retrieve_maintrack_openstack_deployment_details. \
        RetrieveFromDIT(deployment_name)
    if sed_param_ip_version == "ipv4":
        sed_param_ip_version = "ip"
    if "for_services_vm" in sed_param:
        key_to_get_ip = sed_param_connection_type + "_" + sed_param_ip_version \
                        + "v4_" + sed_param
        logging.info("Key to search vm ip is " + key_to_get_ip)
        ip_of_sed_param = dit.get_vnflcm_sed_params(key_to_get_ip)
    else:
        key_to_get_ip = sed_param + "_" + sed_param_connection_type + "_" \
                        + sed_param_ip_version + "_" + "list"
        logging.info("Key to search vm ip is " + key_to_get_ip)
        ip_of_sed_param = dit.get_enm_sed_params(key_to_get_ip)
    logging.info(key_to_get_ip + " IP = " + ip_of_sed_param)
    return ip_of_sed_param


def openstack_client_command(**kwargs):
    """
    :raise TypeError: When unexpected argument is passed in

    Run the openstack client cli command, with the given action and arguments.
    """
    command_type = kwargs.pop('command_type')
    object_type = kwargs.pop('object_type')
    action = kwargs.pop('action')
    command_line_arguments = kwargs.pop('arguments')

    if kwargs:
        raise TypeError('Unexpected **kwargs: %r' % kwargs)

    command_and_arguments = \
        command_type + " " + object_type + " " + action + " " + \
        command_line_arguments + " -f json"

    cli_command_output = common_functions.run_cli_command(
        command_and_arguments)
    cli_command_standard_output = cli_command_output['standard_output']
    output_list = json.loads(cli_command_standard_output)
    return output_list


def parse_command_output(vm_details, key_to_search):
    """
    :param vm_details: Information about the VM returned from CLI command
    :param key_to_search: Key in the command output search for
    :return: Value of the Key

    """
    for vm_detail in vm_details:
        logging.debug(vm_detail[key_to_search])
        return vm_detail[key_to_search]


def check_vm_is_active(vm_details):
    """
    Checks if the VM is ACTIVE.
    :param vm_details: CLI command output
    :raise SystemExit if VM is not in active state
    """
    logging.info("Checking if VM is ACTIVE")
    status = parse_command_output(vm_details, "Status")
    if status.lower() != "active":
        logging.error("VM is not in ACTIVE state. Please selected an active "
                      "VM")
        sys.exit(1)

    logging.info("VM is ACTIVE")


def execute_script_functions(args):
    """
    :param args: Argument list returned by arg parser

    Executes the functions in the script
    """
    common_functions.determine_logging_level(args.verbose)
    base_directory = common_functions.get_utils_base_directory()
    env_setup_file_location = create_pem_key_directory(base_directory)
    os_project_name, os_username, os_password, os_auth_url, openstack_version = \
        get_deployment_details(args.cluster_id)
    create_env_setup_script(cluster_id=args.cluster_id,
                            os_project_name=os_project_name,
                            os_username=os_username,
                            os_password=os_password,
                            os_auth_url=os_auth_url,
                            openstack_version=openstack_version,
                            setup_file_location=env_setup_file_location)

    # This setups the env variables to run Openstack CLI commands
    setup_openstack_env_variables(os_project_name, os_username, os_password,
                                  os_auth_url)
    dit = retrieve_maintrack_openstack_deployment_details. \
        RetrieveFromDIT(args.cluster_id)
    private_key = dit.get_private_key()
    pem_key = create_local_pem_key_file(args.cluster_id, private_key,
                                        env_setup_file_location)
    vm_ip_address = get_sed_params(args.cluster_id, args.vm_name,
                                   args.type_of_connection, args.ip_version)

    if args.copy_pem_to_vm:
        for each_comma_separated_ip in vm_ip_address.split(','):
            copy_pem_file_to_vm(args.vm_name, each_comma_separated_ip, pem_key,
                                args.cluster_id + ".pem")

    if args.run_command:
        output = run_command_on_vm_host(vm_ip_address, pem_key,
                                        args.run_command)
        if args.output_to_screen:
            try:
                common_functions.print_to_screen(
                    output[0].strip(), args.output_to_screen
                )
            except IndexError as exception:
                logging.error(
                    "No value found, see output of error: " + str(exception)
                )
                sys.exit(1)


if __name__ == "__main__":
    config.init(__file__)
    execute_script_functions(parse_args())