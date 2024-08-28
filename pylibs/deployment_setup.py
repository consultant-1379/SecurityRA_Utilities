"""
This script handle setting up a deployment post install or upgrade
"""
import logging
import sys
import stat
import paramiko
import configuration
import argparse

import retrieve_ddp_information as ddp_info
import retrieve_dmt_information as dmt_info
import config
import vm_connector
import common_functions
import MTELoopScripts.etc.pylibs.emt_password_information_client as emt_password_info_client
from MTELoopScripts.etc.pylibs.lib.deployment.cloud import CloudDeployment
from retrieve_maintrack_openstack_deployment_details import RetrieveFromDIT
from product_set import ProductSet
from enm_iso import ENMISO

from distutils.version import StrictVersion
from argparse import Namespace

SETUP_SCRIPT_DIRECTORY = "/var/tmp/MT/deployment_setup_scripts/"
SETUP_COMMANDS = ["easy_install pip", "pip install paramiko"]
CLEANUP_COMMANDS = ["rm -rf /var/tmp/etc", "pip uninstall paramiko -y",
                    "pip uninstall pip -y"]
CONFIG = configuration.UtilsConfig()
NETSIM_ROOT_PASSWORD = CONFIG.get("COMMON_VARIABLES", "netsim_root_password")
ROOT_USER = CONFIG.get("COMMON_VARIABLES", "root_user")
NETSIM_USER = CONFIG.get("COMMON_VARIABLES", "netsim_user")
NETSIM_USER_PASSWORD = CONFIG.get("COMMON_VARIABLES", "netsim_user_password")


class NetsimDDCSetup(object):
    """
    Provides functions to setup DDC on netsims hosts attached to a deployment
    """
    def __init__(self, cluster_id, deployment_type):
        self.cluster_id = cluster_id
        self.deployment_type = deployment_type
        self.base_dir = common_functions.get_utils_base_directory()
        self.ddc_core_rpm = CONFIG.get("COMMON_VARIABLES", "ddc_core_rpm")

        if self.deployment_type == "cloud":
            self.pem_key_location = get_cloud_pem_key(self.base_dir,
                                                      self.cluster_id)

    def get_netsim_hosts(self):
        """
        :return: List of Netsim hosts attached to the deployment
        """
        if self.deployment_type == "cloud":
            dit = RetrieveFromDIT(self.cluster_id)
            netsim_hosts = dit.get_netsim_content()
        elif self.deployment_type == "physical":
            netsim_hosts = dmt_info.search_for_netsim_servers(self.cluster_id)
        else:
            logging.error("Invalid deployment type " + self.deployment_type)
            sys.exit(1)
        return netsim_hosts

    def copy_file_to_host(self, netsim_host, file_path, file_name):
        """
        :param netsim_host: Hostname of the netsim
        :param file_path: Path to the file
        :param file_name: Name of the file

        This function copies a file to a netsim host
        """
        logging.info("Copying " + file_path +
                     " to the following netsim host: " + str(netsim_host))
        remote_file_path = SETUP_SCRIPT_DIRECTORY + file_name
        logging.info("Remote File Path: " + str(remote_file_path))
        common_functions.sftp_file(
            ip_address=netsim_host,
            username=CONFIG.get("COMMON_VARIABLES", "root_user"),
            local_file_path=str(file_path).strip(),
            remote_file_path=str(remote_file_path).strip(),
            deployment_type="physical",
            password=CONFIG.get("COMMON_VARIABLES",
                                "netsim_root_password"),
            private_key=None,
            set_file_permissions=stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
            sftp_command="put")

    def run_script_on_host(self, netsim_host, ssh_client, script):
        """
        :param netsim_host: Host name of the netsim host
        :param ssh_client: SSH client object to the netsim host
        :param script: Path to script

        Execute the ddc setup script on the hosted MT
        """
        logging.info("Executing the following script on " + netsim_host)
        logging.info("- " + str(script))
        command = "sh " + script
        command_output = self.run_command_on_host(command, ssh_client)
        common_functions.get_command_output(command_output)

    @staticmethod
    def run_command_on_host(command, client):
        """
        :param command: Command to run on the host
        :param client: SSH connection to the netsim host
        :return command output

        Runs a command on the netsim host
        """
        logging.info("Executing command: " + str(command))
        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status is not 0:
            logging.error("Command has exited with exit code " +
                          str(exit_status))
            returned_value = stdout.readlines()
            logging.error(returned_value)
            client.close()
            sys.exit(1)
        try:
            returned_value = stdout.readlines()
        except IndexError as exception:
            logging.error("No value found, see output of error: " +
                          str(exception))
            returned_value = ""
        return returned_value

    def setup_ddc_on_host(self, netsim_host, netsim_setup_script_name, ssh):
        """
        :param netsim_host: Netsim hostname
        :param netsim_setup_script_name: Name of the DDC Script
        :param ssh: SSH Connection Object to the host

        Executes the steps to setup DDC for a Netsim host
        """
        netsim_setup_script_path = common_functions.find_file(
            netsim_setup_script_name)
        create_directory_command = "mkdir -p " + SETUP_SCRIPT_DIRECTORY
        self.run_command_on_host(create_directory_command, ssh)
        self.copy_file_to_host(netsim_host, netsim_setup_script_path,
                               netsim_setup_script_name)
        remote_script =\
            SETUP_SCRIPT_DIRECTORY + netsim_setup_script_name +\
            " -t " + self.deployment_type + " -c " + self.cluster_id
        self.run_script_on_host(netsim_host, ssh, remote_script)

    def get_ddc_version_on_netsim(self, ssh_client):
        """
        :param ssh_client: SSH Client object to the netsim host
        :return DDC CORE RPM version on the netsim host
        """
        command = "rpm -qa " + self.ddc_core_rpm
        command_output = self.run_command_on_host(command, ssh_client)
        if command_output:
            rpm_version = command_output[0].split("-")[1]
            logging.info("Netsim Version = " + str(rpm_version))
        else:
            logging.warning("Unable to get version back from netsim")
            logging.debug("Command output = " + str(command_output))
            rpm_version = None

        return rpm_version

    @staticmethod
    def compare_versions(netsim_version, deployment_version):
        """
        :param netsim_version: Version of DDC rpm on the netsim host
        :param deployment_version: Version of DDC rpm on the deployment
        :return: False if the versions do not match. True if they match
        """
        if netsim_version is None:
            logging.info("RPM not installed on netsim host")
            versions_match = False
        elif StrictVersion(netsim_version) == StrictVersion(
                deployment_version):
            logging.info("Versions match therefore not updating "
                         "DDC on netsim")
            versions_match = True
        else:
            logging.info("Latest DDC core version now matching the version "
                         "on netsim. Therefore updating netsim DDC.")
            versions_match = False

        return versions_match

    def update_ddc_rpm_on_netsim(self, latest_ddc_core_version,
                                 netsim_ddc_version, ssh):
        """
        :param latest_ddc_core_version : DDC core from latest green product set
        :param netsim_ddc_version: Version of DDC on the netsim
        :param ssh: SSH Connection object

        This function updates the ddc rpm on the netsim host
        """
        versions_match = self.compare_versions(netsim_ddc_version,
                                               latest_ddc_core_version)
        if versions_match:
            logging.info("DDC version on netsim and deployment match")
        else:
            logging.info("Updating DDC core version")
            self.remove_installed_ddc_version(ssh)
            self.download_ddc_rpm_on_host(latest_ddc_core_version, ssh)

    def remove_installed_ddc_version(self, ssh):
        logging.info("Removing DDC core from host")
        is_ddc_core_installed_command = "rpm -qa " + self.ddc_core_rpm
        is_installed = self.run_command_on_host(is_ddc_core_installed_command,
                                                ssh)
        logging.info("is installed " + str(is_installed))
        if is_installed:
            command = "rpm -e " + self.ddc_core_rpm
            self.run_command_on_host(command, ssh)
        else:
            logging.info("No version installed nothing to remove")

    def remove_ddc_packages_if_exist(self, ssh):
        remove_command = "rm -rf ERICddc*"
        self.run_command_on_host(remove_command, ssh)

    def download_ddc_rpm_on_host(self, ddc_core_version, ssh_object):
        self.remove_ddc_packages_if_exist(ssh_object)
        wget_command = "wget --no-check-certificate --quiet -e " \
                       "use_proxy=yes -e https_proxy=atproxy1.athtem.eei" \
                       ".ericsson.se:3128 "
        download_ddc_command = "https://arm1s11-eiffel004.eiffel.gic.ericsson.se:" \
                               "8443/nexus/content/repositories/releases" \
                               "/com/ericsson/oss/itpf/monitoring/" \
                               "ERICddccore_CXP9035927/" + ddc_core_version + \
                               "/ERICddccore_CXP9035927-" + \
                               ddc_core_version + ".rpm"

        self.run_command_on_host(
            wget_command + download_ddc_command,
            ssh_object)
        install_command = "rpm -ivh ERICddc* --nodeps"
        start_command = "service ddc start"
        self.run_command_on_host(install_command, ssh_object)
        self.run_command_on_host(start_command, ssh_object)
        self.run_command_on_host("rm -rf ERICddc*", ssh_object)


class DeploymentDDCSetup(object):
    """
    Provides functions that can setup ddc on a deployment.
    Can be used for cloud/physical deployments. Handles copying ddc setup
    scripts to a deployment and executing that script on the deployment
    """
    def __init__(self, cluster_id, deployment_type):
        self.cluster_id = cluster_id
        self.deployment_type = deployment_type
        self.base_dir = common_functions.get_utils_base_directory()

        # Setup Openstack ENV Variables for cloud
        if self.deployment_type == "cloud":
            os_project_name, os_username, os_password, os_auth_url, openstack_version =\
                vm_connector.get_deployment_details(cluster_id)
            vm_connector.setup_openstack_env_variables(os_project_name,
                                                       os_username,
                                                       os_password,
                                                       os_auth_url)

    def get_user_details_for_physical(self):
        """
        :return the user credentials for Physical MS
        """
        password = emt_password_info_client.determine_lms_password_or_set_default(self.cluster_id)
        return ROOT_USER, password

    def copy_ddc_script_to_host(self, host_ip, ddc_script_path,
                                ddc_script_name):
        """
        :param host_ip: IP of the host to copy the file to
        :param ddc_script_path: Path to the DDC Setup script to run
        :param ddc_script_name: Name of the DDC Setup Script

        This function copies the  ddc setup to the host ip
        """
        logging.info("Copying " + ddc_script_path + " to " + host_ip)
        remote_file_path = SETUP_SCRIPT_DIRECTORY + "/" + ddc_script_name
        if self.deployment_type == "physical":
            username, password = self.get_user_details_for_physical()
            private_key = None

        elif self.deployment_type == "cloud":
            username = CONFIG.get("MT_Cloud", "cloud_vm_username")
            pem_key_path = get_cloud_pem_key(self.base_dir, self.cluster_id)
            private_key = paramiko.RSAKey.from_private_key_file(pem_key_path)
            password = None
        else:
            logging.error("Invalid Deployment Type")
            sys.exit(1)
        common_functions.sftp_file(
            ip_address=host_ip,
            username=username,
            local_file_path=ddc_script_path,
            remote_file_path=remote_file_path,
            deployment_type=self.deployment_type,
            password=password,
            private_key=private_key,
            set_file_permissions=stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
            sftp_command="put")

    def get_ddp_details(self, item_to_search):
        """
        :param item_to_search: Key to search for in deployments_ddp.json
        :return: Value for the key from the ddp json file
        """
        ddp_server_name = ddp_info.get_specific_deployment_detail(
            self.cluster_id, item_to_search)
        logging.info(item_to_search + " : " + ddp_server_name)
        return ddp_server_name

    def execute_ddc_setup(self, host_ip, ddc_script, setup_ddc_on_rnl,
                          requires_hophost):
        """
        :param host_ip:
        :param ddc_script: Path to the ddc setup script
        :param setup_ddc_on_rnl:
        :param requires_hophost:

        Execute the ddc setup script on the host
        """
        logging.info("Executing DDC Setup on " + host_ip)
        logging.info("Script to execute: " + str(ddc_script))
        command = "sh " + SETUP_SCRIPT_DIRECTORY + ddc_script
        if not setup_ddc_on_rnl:
            netsim = NetsimDDCSetup(self.cluster_id, self.deployment_type)
            netsim_hosts = netsim.get_netsim_hosts()
            netsim_argument = ",".join(netsim_hosts)
        else:
            netsim_argument = ""
        if self.deployment_type == "physical":
            ddp_server_name = self.get_ddp_details("ddp_hostname")
            ddp_server_cron = self.get_ddp_details("cron")
            command =\
                command + " -c " + self.cluster_id + " -d " +\
                ddp_server_name + " -r \"" + ddp_server_cron + "\" -n " +\
                netsim_argument
            username, password = self.get_user_details_for_physical()
            command_output = common_functions.ssh_run_command(
                server_ip=host_ip,
                command=command,
                username=username,
                password=password)
            if command_output:
                common_functions.get_command_output(command_output)
        elif self.deployment_type == "cloud":
            ddp = CloudDeployment(self.cluster_id).ddp
            ddp_server_name = ddp.hostname
            ddp_server_cron = ddp.cron
            command = "sudo " + command + " -c " + self.cluster_id + \
                      " -n " + ddp_server_name + " -r " + \
                      ddp_server_cron
            if not setup_ddc_on_rnl:
                command = command + " -b " + netsim_argument
            else:
                if requires_hophost:
                    command = command + " -p"
            logging.info("Running command: " + command)
            pem_key_location = get_cloud_pem_key(self.base_dir,
                                                 self.cluster_id)
            vm_connector.run_command_on_vm_host(host_ip, pem_key_location,
                                                command)
        else:
            logging.error("Invalid Deployment Type")
            sys.exit(1)


class EmpFunctionalitySetup(object):
    """
    Provides functions to setup EMP functionality. Can be used only for
    cloud deployments.
    """
    def __init__(self, deployment_name):
        os_project_name, os_username, os_password, os_auth_url, openstack_version = \
            vm_connector.get_deployment_details(deployment_name)
        vm_connector.setup_openstack_env_variables(os_project_name,
                                                   os_username,
                                                   os_password,
                                                   os_auth_url)
        self.deployment_name = deployment_name
        self.base_directory = common_functions.get_utils_base_directory()
        self.pem_key_path = get_cloud_pem_key(self.base_directory,
                                              self.deployment_name)
        self.emp_ip_address = vm_connector.\
            get_sed_params(self.deployment_name, "emp", "external", "ipv4")
        self.root_username = ROOT_USER
        self.wlvm_password = emt_password_info_client \
            .determine_wlvm_password_or_set_default(self.deployment_name)

    def setup_dependencies(self):
        """
        Runs each command in the list to install required modules
        """
        logging.info("Setting up dependencies")
        for command in SETUP_COMMANDS:
            vm_connector.run_command_on_vm_host(
                self.emp_ip_address, self.pem_key_path,
                "sudo " + command + " > /dev/null 2>&1")

    def remove_dependencies(self):
        """
        Runs each command in the list to remove any modules and directories
        that were setup
        """
        logging.info("Removing dependencies")
        for command in CLEANUP_COMMANDS:
            vm_connector.run_command_on_vm_host(
                self.emp_ip_address, self.pem_key_path,
                "sudo " + command)

    def copy_etc_folder_to_emp(self):
        """
        Copies the etc folder in the utils repo over to EMP so that
        ssh_operator can be run
        """
        logging.info("Copying the etc folder in the utils repo over to EMP")
        private_key = paramiko.RSAKey.from_private_key_file(self.pem_key_path)
        password = None
        local_file_path = self.base_directory + "/etc"
        remote_file_path = "/var/tmp/"
        common_functions.sftp_file(
            ip_address=self.emp_ip_address,
            username=CONFIG.get("MT_Cloud", "cloud_vm_username"),
            local_file_path=str(local_file_path).strip(),
            remote_file_path=str(remote_file_path).strip(),
            deployment_type="cloud",
            password=password,
            private_key=private_key,
            set_file_permissions=None, sftp_command="put_all")

    def setup_passwordless_connection_between_emp_and_wlvm(self, wlvm_ip):
        """
        :param wlvm_ip:
        Sets up passwordless connection between EMP and the WLVM
        """
        logging.info("Setting up passwordless connection between "
                     "EMP and the WLVM")
        command = "python /var/tmp/etc/ssh_operator.py -c -i " \
                  + wlvm_ip + " -u " + self.root_username + " -p " + self.wlvm_password
        vm_connector.run_command_on_vm_host(
            self.emp_ip_address, self.pem_key_path,
            command)

    def setup_aliases(self, wlvm_ip):
        """
        :param wlvm_ip:
        Sets up aliases in EMP
        """
        command_output = vm_connector.run_command_on_vm_host(
            self.emp_ip_address, self.pem_key_path,
            "cat /home/cloud-user/.bashrc | { grep \"alias "
            "connect_to_wlvm\" || true; }")
        if str(command_output) == "[]":
            logging.info("Setting up aliases in EMP")
            alias_command = "echo \"alias connect_to_wlvm='ssh root@" + \
                            wlvm_ip + "'\" >> /home/cloud-user/.bashrc"
            source_command = "source /home/cloud-user/.bashrc"
            final_command = alias_command + " && " + source_command
            vm_connector.run_command_on_vm_host(
                self.emp_ip_address, self.pem_key_path,
                final_command)
        else:
            logging.info("Alias already setup")

    def copy_pem_key_to_wlvm(self, wlvm_ip):
        """
        :param wlvm_ip:
        Copies pem key to the Workload VM
        """
        logging.info("Copying the pem key in the openstack slave over to "
                     "the WLVM")
        pem_key_name = self.deployment_name + ".pem"
        local_file_path = self.base_directory + "/pem_keys/" + pem_key_name
        remote_pem_key_location = "/var/tmp/pem_key"
        ssh = common_functions.get_ssh_client_for_physical(wlvm_ip,
                                                           self.root_username,
                                                           self.wlvm_password)
        ssh.exec_command("mkdir -p " + remote_pem_key_location)
        ssh.close()
        common_functions.sftp_file(
            ip_address=wlvm_ip, username=self.root_username,
            local_file_path=local_file_path,
            private_key=None,
            remote_file_path=remote_pem_key_location + "/" + pem_key_name,
            deployment_type="physical", password=self.wlvm_password,
            set_file_permissions=stat.S_IRUSR | stat.S_IWUSR,
            sftp_command="put")

    def verify_pem_key_in_wlvm(self, wlvm_ip):
        """
        :param wlvm_ip:
        Verifies pem key in the Workload VM
        """
        logging.info("Verifying the pem key in the WLVM")
        remote_pem_key = "/var/tmp/pem_key/" + self.deployment_name + ".pem"
        ssh_command = "ssh -o UserKnownHostsFile=/dev/null -o " \
                      "StrictHostKeyChecking=no -i " + remote_pem_key + \
                      " cloud-user@" + self.emp_ip_address + \
                      " \"echo \"SSH connection established\"\""
        logging.info("Executing command:")
        logging.info(ssh_command)
        ssh = common_functions.get_ssh_client_for_physical(wlvm_ip,
                                                           self.root_username,
                                                           self.wlvm_password)
        stdin, stdout, stderr = \
            ssh.exec_command(ssh_command)
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()
        if exit_status is not 0:
            logging.error("Command has exited with exit code " +
                          str(exit_status))
            returned_value = stdout.readlines()
            logging.error(returned_value)
            sys.exit(1)


def parse_arguments():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    ------------
    This script requires a cluster ID, deployment type and setup steps

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -c ieatenmpca05 -t cloud
    --setup_ddc --setup_ddc_on_rnl --requires_hophost
    ''' + sys.argv[0] + ''' -c ieatenmpca05 -t cloud
    --setup_ddc
    ''' + sys.argv[0] + ''' -c 306 -t physical
    --setup_passwordless_connection_from_ms
    ''' + sys.argv[0] + ''' -c ieatenmpca05 -t cloud
    --setup_passwordless_connection_to_emp
    ''',
        epilog=''''''
    )
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-c", "--cluster_id",
                        help="Cluster ID of the deployment being used",
                        required=True)
    parser.add_argument("-t", "--deployment_type",
                        help="Specify the deployment Type",
                        required=True,
                        choices=['cloud', 'physical'])
    parser.add_argument("--setup_ddc", help="Flag to run DDC Setup on the "
                                            "specified deployment"
                                            " to the specified VM", nargs='?',
                        const=True)
    parser.add_argument("--setup_ddc_on_rnl", help="Flag to run DDC Setup on "
                                                   "a Real Node deployment"
                                                   "and ignore netsims",
                        nargs='?',
                        const=True)
    parser.add_argument("--requires_hophost", help="Flag to setup DDC"
                                                   " with Hophost proxy",
                        nargs='?',
                        const=True)
    parser.add_argument("--setup_passwordless_connection_to_emp",
                        help="Flag to setup passwordless connection from EMP "
                             "and the WLVM of a cloud deployment "
                             "to the specified VM", nargs='?',
                        const=True)
    parser.add_argument("--setup_passwordless_connection_from_ms",
                        help="Flag to setup passwordless connection from"
                             " the MS to the Netsims mapped to a"
                             " specified deployment", nargs='?', const=True)

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def set_deployment_setup_directory(deployment_type, host_ip, cluster_id,
                                   action):
    """
    :param deployment_type:
    :param host_ip:
    :param cluster_id:
    :param action: Create or Remove

    Creates/removes the deployment setup directory on the host
    """
    command = common_functions.get_directory_setup_command(action)
    logging.info("Command " + str(command))
    if deployment_type == "physical":
        lms_password = emt_password_info_client.determine_lms_password_or_set_default(cluster_id)
        ssh_client = common_functions.get_ssh_client_for_physical(host_ip, ROOT_USER, lms_password)
    elif deployment_type == "cloud":
        ssh_client = vm_connector.get_ssh_client(
            host_ip, get_cloud_pem_key(
                common_functions.get_utils_base_directory(),
                cluster_id))
    else:
        logging.error("Invalid Deployment Type: " + deployment_type)
        sys.exit(1)
    try:
        ssh_client.exec_command(command + " " + SETUP_SCRIPT_DIRECTORY)
    except IOError as error:
        logging.error("Issue running command on " + host_ip)
        logging.error(str(error))
    ssh_client.close()


def get_cloud_pem_key(base_dir, cluster_id):
    """
    :param base_dir
    :param cluster_id
    :return: The pem key path required to connect to cloud deployments
    """
    dit = RetrieveFromDIT(cluster_id)
    pem_key = dit.get_private_key()
    pem_key_path = vm_connector. \
        create_pem_key_directory(base_dir)
    local_pem_key = vm_connector.create_local_pem_key_file(
        cluster_id, pem_key, pem_key_path)
    return local_pem_key


def remove_any_non_core_ddc_versions(netsim_instance, ssh_object):
    non_core_version = check_if_non_core_version(netsim_instance, ssh_object)

    if non_core_version:
        logging.info("non core version exists on netsim, must be removed")
        remove_non_ddc_core(netsim_instance, ssh_object)
    else:
        logging.info("No non core versions installed")


def remove_non_ddc_core(netsim_instance, ssh_object):
    logging.info("removing non core version")
    command = "rpm -e ERICddc_CXP9030294"
    netsim_instance.run_command_on_host(command, ssh_object)


def check_if_non_core_version(netsim_instance, ssh_object):
    logging.info("Checking if a non core version of ddc exists!!!")
    command = "rpm -qa ERICddc_CXP9030294"
    netsim_instance.run_command_on_host(command, ssh_object)
    is_non_core_on_netsim = netsim_instance.run_command_on_host(command,
                                                                ssh_object)
    logging.info("IS NON CORE : " + str(is_non_core_on_netsim))
    return is_non_core_on_netsim


def get_ddc_core_version_from_iso(ddc_core_rpm):
    latest_product_set_command = "https://cifwk-oss.lmera.ericsson.se/" \
                                 "getLastGoodProductSetVersion/?productSet=ENM"
    latest_green_product_set = common_functions.return_url_response(
        latest_product_set_command)
    if latest_green_product_set is None:
        logging.error("Unable to get green product set version")
        sys.exit(1)
    logging.info("Latest green Product set : " + latest_green_product_set)
    drop_split_versions = latest_green_product_set.split(".")
    drop = drop_split_versions[0] + "." + drop_split_versions[1]
    logging.info("Drop is : " + drop)

    product_set = ProductSet(latest_green_product_set)
    iso_from_ps = product_set.get_enm_iso(drop)
    logging.info("ISO is : " + iso_from_ps)

    iso = ENMISO(iso_from_ps)

    ddc_core_version = iso.parse_iso_content_for_field(ddc_core_rpm,
                                                       "version")
    logging.info("DDC core version is : " + ddc_core_version)
    return ddc_core_version


def execute_ddc_setup_on_netsim(netsim_instance, netsim_hosts, ddc_core_rpm):
    """
    :param netsim_instance: Instance of NetsimDDCSetup class
    :param netsim_hosts: List of netsim hosts
    :param ddc_core_rpm: Version of DDC core on the deployment
    Executes the DDC Setup steps on each host in the netsim hosts list
    """
    latest_ddc_core_version = get_ddc_core_version_from_iso(ddc_core_rpm)
    logging.info("DDC core version from latest ISO : " +
                 latest_ddc_core_version)
    for host in netsim_hosts:
        ssh_object = common_functions.get_ssh_client_for_physical(
            host, ROOT_USER, NETSIM_ROOT_PASSWORD)

        remove_any_non_core_ddc_versions(netsim_instance, ssh_object)

        netsim_instance.setup_ddc_on_host(host, "setup_ddp_on_netsim.sh",
                                          ssh_object)

        netsim_ddc_version = netsim_instance.get_ddc_version_on_netsim(
            ssh_object)

        netsim_instance.update_ddc_rpm_on_netsim(latest_ddc_core_version,
                                                 netsim_ddc_version,
                                                 ssh_object)
        netsim_instance.run_command_on_host(str("rm -rf " +
                                                SETUP_SCRIPT_DIRECTORY),
                                            ssh_object)
        ssh_object.close()


def setup_passwordless_connection_from_ms_to_netsim_host(netsim_host, ms_ip, netsim_username,
                                                         netsim_password, cluster_id):
    """
    :param netsim_host:
    :param ms_ip:
    :param netsim_username:
    :param netsim_password:
    :param cluster_id:

    Sets up passwordless connection to a specified netsim host from
    a specified ms as a specified user
    """
    remote_script_command = "python /var/tmp/MT/etc/ssh_operator.py -c " + \
                            "-i " + netsim_host + " -u " + netsim_username + \
                            " -p " + netsim_password + " 2>&1"
    lms_password = emt_password_info_client.determine_lms_password_or_set_default(cluster_id)
    command_output = \
        common_functions.\
        ssh_run_command(server_ip=ms_ip,
                        command=remote_script_command,
                        username=ROOT_USER,
                        password=lms_password)
    common_functions.get_command_output(command_output)


def execute_functions(args):
    """
    :param args: Argument list passed into the script

    Executes the functions in the script.
    """
    common_functions.determine_logging_level(args.verbose)
    logging.debug(args.deployment_type)
    if args.setup_ddc:
        ddc_setup = DeploymentDDCSetup(args.cluster_id, args.deployment_type)
        logging.info("Setting up DDC for " + args.cluster_id)

        if args.deployment_type == "physical":
            setup_script_name = "setup_ddp_on_physical.sh"
            ip_to_run_on = dmt_info.search_for_ms_ip(args.cluster_id)
            ddc_setup_script = common_functions.find_file(setup_script_name)

        elif args.deployment_type == "cloud":
            setup_script_name = "setup_ddp_on_cloud.sh"
            ip_to_run_on = vm_connector.\
                get_sed_params(args.cluster_id, "esmon", "external", "ipv4")
            ddc_setup_script = common_functions.find_file(
                setup_script_name)
        else:
            logging.error("Unknown Deployment Type: " +
                          str(args.deployment_type))
            sys.exit(1)

        logging.debug("Host IP: " + ip_to_run_on)
        logging.debug("DDC Setup Script: " + ddc_setup_script)
        logging.info("Creating a temporary directory on the host to store "
                     "the setup script")
        set_deployment_setup_directory(args.deployment_type, ip_to_run_on,
                                       args.cluster_id, "create")

        ddc_setup.copy_ddc_script_to_host(ip_to_run_on, ddc_setup_script,
                                          setup_script_name)
        ddc_setup.execute_ddc_setup(ip_to_run_on, setup_script_name,
                                    args.setup_ddc_on_rnl,
                                    args.requires_hophost)

        logging.info("Removing temporary directory on the host")
        set_deployment_setup_directory(args.deployment_type, ip_to_run_on,
                                       args.cluster_id, "remove")

    if args.setup_ddc and not args.setup_ddc_on_rnl:
        netsim = NetsimDDCSetup(args.cluster_id, args.deployment_type)
        netsim_hosts = netsim.get_netsim_hosts()
        logging.info("Setting up DDC on the following netsim boxes: " +
                     str(netsim_hosts))
        execute_ddc_setup_on_netsim(netsim, netsim_hosts, netsim.ddc_core_rpm)

    if args.setup_passwordless_connection_to_emp:
        dit = RetrieveFromDIT(args.cluster_id)
        wlvm_ip = dit.get_workload_content("ip")
        setup_passwordless_connection = \
            EmpFunctionalitySetup(args.cluster_id)
        vm_connector.args = Namespace(
            cluster_id=args.cluster_id,
            vm_name="emp",
            type_of_connection="external",
            ip_version="ipv4",
            copy_pem_to_vm="True",
            run_command="",
            verbose=False)
        vm_connector.execute_script_functions(vm_connector.args)
        setup_passwordless_connection.setup_dependencies()
        setup_passwordless_connection.copy_etc_folder_to_emp()
        setup_passwordless_connection.\
            setup_passwordless_connection_between_emp_and_wlvm(wlvm_ip)
        setup_passwordless_connection.setup_aliases(wlvm_ip)
        setup_passwordless_connection.copy_pem_key_to_wlvm(wlvm_ip)
        setup_passwordless_connection.verify_pem_key_in_wlvm(wlvm_ip)
        setup_passwordless_connection.remove_dependencies()

    if args.setup_passwordless_connection_from_ms:
        if args.deployment_type == "physical":
            netsim = NetsimDDCSetup(args.cluster_id, args.deployment_type)
            netsim_hosts = netsim.get_netsim_hosts()
            logging.debug("Netsim Hosts:")
            logging.debug(str(netsim_hosts))
            ms_ip = dmt_info.search_for_ms_ip(args.cluster_id)

            for netsim_host in netsim_hosts:
                logging.info("Setting up passwordless connection to "
                             "netsim: " + netsim_host + " as root user")
                setup_passwordless_connection_from_ms_to_netsim_host(
                    netsim_host, ms_ip, ROOT_USER, NETSIM_ROOT_PASSWORD, args.cluster_id)
                logging.info("Setting up passwordless connection to "
                             "netsim: " + netsim_host + " as netsim user")
                setup_passwordless_connection_from_ms_to_netsim_host(
                    netsim_host, ms_ip, NETSIM_USER,
                    NETSIM_USER_PASSWORD, args.cluster_id)
        else:
            logging.error("Must be a physical deployment in order "
                          "to create a passwordless connection "
                          "between the MS and the Netsims")
            sys.exit(1)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_arguments())