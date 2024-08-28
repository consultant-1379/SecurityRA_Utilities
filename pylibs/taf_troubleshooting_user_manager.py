"""
 This script is used to manage the TAF user that is used
 for all testware that requires passwordless connection to
 the MS
"""
import subprocess
import sys
import logging

from MTELoopScripts.etc.pylibs import argparse, config, common_functions, configuration,\
    retrieve_dmt_information, emt_password_information_client

CONFIG = configuration.UtilsConfig()
EMT_API_URL = '{0}/api'.format(CONFIG.get('MT_Cloud', 'emt_url'))
CREATE_TROUBLESHOOTING_USER_PLAYBOOK = 'MTELoopScripts/ansible/manage_taf_troubleshooting_user/' \
                                       'tasks/create_taf_troubleshooting_user.yml'
DELETE_TROUBLESHOOTING_USER_PLAYBOOK = 'MTELoopScripts/ansible/manage_taf_troubleshooting_user/' \
                                       'tasks/delete_taf_troubleshooting_user.yml'


def parse_args():
    """
    This function parses the passed in system arguments.
    :return parser.parse_args():
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    ------------
    This will create or delete a TAF troubleshooting user for any testware that requires
    passwordless connection to the MS

    Examples:
    ------------
    ''' + sys.argv[0] + ''' -c 339 -cu
    ''' + sys.argv[0] + ''' --cluster_id 339 --delete_taf_user
    ''',
        epilog=''''''
    )
    parser.add_argument("-c", "--cluster_id",
                        help="Environment to create the TAF troubleshooting user for",
                        required=True)
    parser.add_argument("-cu", "--create_taf_user",
                        help="Creates the TAF troubleshooting user", action="store_true")
    parser.add_argument("-du", "--delete_taf_user",
                        help="Deletes the TAF troubleshooting user", action="store_true")
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")

    if not sys.argv[1:]:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def setup_passwordless_connection_from_taf_user_of_ms_to_root_of_wlvm(
        cluster_id, taf_username, taf_password):
    """
    Sets up password less connection between troubleshooting_user
    of a lms and root user of wlvm for a given deployment
    :arg cluster_id
    :arg taf_username
    :arg taf_password
    """
    logging.info("Setting up passwordless connection between taf_user of lms and wlvm")
    ms_ip = retrieve_dmt_information.search_for_ms_ip(cluster_id)
    wlvm_ip = retrieve_dmt_information.search_for_workload_vm_ip(cluster_id)
    wlvm_password = emt_password_information_client\
        .determine_wlvm_password_or_set_default(cluster_id)
    remote_script_command = "python /var/tmp/MT/etc/ssh_operator.py -c" + \
                            " -i " + wlvm_ip + " -u " + "root" + \
                            " -p " + wlvm_password + " 2>&1"
    command_output = \
        common_functions.\
        ssh_run_command(server_ip=ms_ip,
                        command=remote_script_command,
                        username=taf_username,
                        password=taf_password)
    common_functions.get_command_output(command_output)


def run_shell_command(command):
    """
    This function runs a shell command on the host, gets its output and checks the exit code
    :arg command
    """
    logging.info('Running command: {0}'.format(command))
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    for line in process.stdout:
        logging.info(line)
    process.wait()
    if process.returncode != 0:
        logging.error('Failed to run command. Exiting...')
        sys.exit(1)


def create_new_troubleshooting_user(cluster_id, taf_username, taf_password):
    """
    This function calls a playbook to create a new troubleshooting user in
    a physical environment's MS
    :arg cluster_id
    :arg taf_username
    :arg taf_password
    """
    create_new_troubleshooting_user_command \
        = 'sudo ansible-playbook {0} --extra-vars "cluster_id={1} username={2} password={3} ' \
          'group=quarantine"'.format(CREATE_TROUBLESHOOTING_USER_PLAYBOOK, cluster_id,
                                     taf_username, taf_password)
    run_shell_command(create_new_troubleshooting_user_command)


def delete_troubleshooting_user(cluster_id):
    """
    This function calls a playbook to delete a new troubleshooting user in
    a physical environment's MS
    :arg cluster_id
    """
    taf_username, taf_password = retrieve_dmt_information\
        .retrieve_taf_troubleshooting_user_details_from_dmt(cluster_id)
    delete_troubleshooting_user_command =\
        'sudo ansible-playbook {0} --extra-vars "cluster_id={1} username={2}"'\
        .format(DELETE_TROUBLESHOOTING_USER_PLAYBOOK, cluster_id, taf_username)
    run_shell_command(delete_troubleshooting_user_command)


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    """
    if args.verbose:
        common_functions.determine_logging_level(args.verbose)
    if args.create_taf_user:
        taf_username, taf_password = retrieve_dmt_information\
            .retrieve_taf_troubleshooting_user_details_from_dmt(args.cluster_id)
        create_new_troubleshooting_user(args.cluster_id, taf_username, taf_password)
        setup_passwordless_connection_from_taf_user_of_ms_to_root_of_wlvm(
            args.cluster_id, taf_username, taf_password)
    if args.delete_taf_user:
        delete_troubleshooting_user(args.cluster_id)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())