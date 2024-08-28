"""
 This script retrieves the Maintrack Openstack/Cloud Deployment Details.
"""

import logging
import sys
import json
import os

import argparse
import config
import common_functions
import configuration

CONFIG = configuration.UtilsConfig()


class NetsimsNotFound(Exception):
    pass


class EmptyWorkload(Exception):
    pass


class EmptySed(Exception):
    pass


class EmptyVnflcm(Exception):
    pass


class RetrieveFromDIT(object):
    """
    Retrieves information from DIT
    """

    def __init__(self, deployment_id):
        """
        Initialize a RetrieveFromDIT Object
        :param deployment_id: Hostname of the cloud deployment
        """
        self.deployment_id = deployment_id

    def get_project_id(self):
        """
        :return: Project ID for the deployment
        """
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/deployments/",
            query="?q=name=" + self.deployment_id,
            field="project_id"
        )
        logging.debug(str(deployment_json))
        try:
            return deployment_json[0]["project_id"]
        except KeyError as error:
            logging.error("Unable to find Project ID")
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_pod_id(self):
        """
        :return: Pod ID for the deployment
        """
        project_id = self.get_project_id()
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/projects/",
            query=project_id,
            field="pod_id"
        )
        logging.debug(str(deployment_json))
        try:
            return deployment_json["pod_id"]
        except KeyError as error:
            logging.error("Unable to find POD ID")
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_project_content(self, key_to_search):
        """
        :return: Project content for the deployment
        :param key_to_search: Key to search for in Project contents
        """
        project_id = self.get_project_id()
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/projects/",
            query=project_id,
            field=key_to_search
        )
        logging.debug(str(deployment_json))
        try:
            logging.debug(str(deployment_json))
            return deployment_json[key_to_search]
        except KeyError as error:
            logging.error("Unable to find " + key_to_search)
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_pod_content(self, key_to_search):
        """
        :return: specific POD content for the deployment
        :param key_to_search: Key to search for in POD contents
        """
        pod_id = self.get_pod_id()
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/pods/",
            query=pod_id,
            field=key_to_search
        )
        logging.debug(str(deployment_json))
        try:
            return deployment_json[key_to_search]
        except KeyError as error:
            logging.error("Unable to find " + key_to_search)
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_document_id(self, schema_name):
        """
        :param schema_name
        :return: When a schema name is specified this function returns the
        document_id for the deployment
        """
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/deployments/",
            query="?q=name=" + self.deployment_id,
            field="documents"
        )
        logging.debug(str(deployment_json))
        try:
            documents = deployment_json[0]['documents']
            for document in documents:
                if document["schema_name"] == schema_name:
                    return document["document_id"]
        except KeyError as error:
            logging.error("Unable to find " + schema_name + " id")
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_workload_content(self, key_to_search, ignore_flag=False):
        """
        :param key_to_search
        :param ignore_flag
        :return: key_to_search in the workload document.
                 If ignore flag is set to true, this function will not fail
                 if the deployment has no workload vm
        """
        workload_id = self.get_document_id("workload")
        workload_value = ""
        try:
            if not workload_id:
                raise EmptyWorkload
            deployment_json = self.run_dit_rest_call(
                deployment_detail="/api/documents/",
                query=workload_id,
                field="content")
            logging.debug(str(deployment_json))
            workload_value = deployment_json["content"]["vm"][0][key_to_search]
            if not workload_value:
                raise EmptyWorkload
        except (KeyError, EmptyWorkload) as error:
            if not ignore_flag:
                logging.error("Unable to find " + key_to_search)
                logging.error(error.__class__.__name__)
                sys.exit(1)
            else:
                logging.warning("The given deployment has no " + key_to_search)

        return workload_value

    def get_director_content(self, key_to_search, ignore_flag=False):
        """
        :param key_to_search
        :param ignore_flag
        :return: key_to_search in the workload document.
                 If ignore flag is set to true, this function will not fail
                 if the deployment has no workload vm
        """
        director_id = self.get_document_id("director")
        workload_value = ""
        try:
            if not director_id:
                raise EmptyWorkload
            deployment_json = self.run_dit_rest_call(
                deployment_detail="/api/documents/",
                query=director_id,
                field="content")
            logging.debug(str(deployment_json))
            director_value = deployment_json["content"]["vm"][0][key_to_search]
            if not director_value:
                raise EmptyWorkload
        except (KeyError, EmptyWorkload) as error:
            if not ignore_flag:
                logging.error("Unable to find " + key_to_search)
                logging.error(error.__class__.__name__)
                sys.exit(1)
            else:
                logging.warning("The given deployment has no " + key_to_search)

        return director_value

    def get_enm_sed_id(self):
        """
        :return: returns ENM SED ID for a given deployment
        """
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/deployments/",
            query="?q=name=" + self.deployment_id,
            field="enm"
        )
        logging.debug(str(deployment_json))
        try:
            sed_id = deployment_json[0]["enm"]["sed_id"]
            return sed_id
        except KeyError as error:
            logging.error("Unable to find ENM SED ID")
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_enm_sed_content(self, ignore_flag=False):
        """
        :return: returns ENM SED content associated with the given deployment
        """
        sed_id = self.get_enm_sed_id()
        sed_content = ""
        try:
            if not sed_id:
                raise EmptySed
            sed_json = self.run_dit_rest_call(
                deployment_detail="/api/documents/",
                query=sed_id,
                field="content")
            logging.debug(str(sed_json))
            sed_content = sed_json["content"]
            if not sed_content:
                raise EmptySed
        except (KeyError, EmptySed) as error:
            if not ignore_flag:
                logging.error("Unable to find ENM sed content")
                logging.error(error.__class__.__name__)
                sys.exit(1)
            else:
                logging.warning("The given deployment has no sed content")

        return sed_content

    def get_vnflcm_sed_content(self, ignore_flag=False):
        """
        :return: returns VNF LCM SED content associated with the given
        deployment
        """
        sed_id = self.get_document_id("vnflcm_sed_schema")
        sed_content = ""
        try:
            if not sed_id:
                raise EmptyVnflcm
            sed_json = self.run_dit_rest_call(
                deployment_detail="/api/documents/",
                query=sed_id,
                field="content")
            logging.debug(str(sed_json))
            sed_content = sed_json["content"]
            if not sed_content:
                raise EmptyVnflcm
        except (KeyError, EmptyVnflcm) as error:
            if not ignore_flag:
                logging.error("Unable to find VNF LCM SED content")
                logging.error(error.__class__.__name__)
                sys.exit(1)
            else:
                logging.warning(
                    "The given deployment has no VNF LCM SED content")

        return sed_content

    def get_vnflcm_sed_ha_status(self):
        """
        :return: VNF LCM SED HA status associated with the given
        deployment
        """
        sed_ha_status = ""
        try:
            sed_id = self.get_document_id("vnflcm_sed_schema")
            if not sed_id:
                raise EmptyVnflcm
            sed_json = self.run_dit_rest_call(
                deployment_detail="/api/documents/",
                query=sed_id,
                field="ha")
            logging.debug("Returned 'ha' field from SED: " + str(sed_json))
            sed_ha_status = sed_json["ha"]
            if not sed_ha_status:
                raise EmptyVnflcm
        except (KeyError, EmptyVnflcm) as error:
            sed_ha_status = "False"
            logging.warning(
                "The given deployment has no VNF LCM SED HA status")

        return sed_ha_status

    def get_httpd_fqdn_content(self, ignore_flag=False):
        """
        :return: HTTPD FQDN content associated with the given
        deployment
        """
        httpd_fqdn = self.get_enm_sed_content()
        try:
            httpd_fqdn = httpd_fqdn["parameter_defaults"]["httpd_fqdn"]
            if not httpd_fqdn:
                raise EmptySed
        except (KeyError, EmptySed) as error:
            try:
                httpd_fqdn = httpd_fqdn["parameters"]["httpd_fqdn"]
                if not httpd_fqdn:
                    raise EmptySed
            except (KeyError, EmptySed) as error:
                if not ignore_flag:
                    logging.error("Unable to find HTTPD FQDN content")
                    logging.error(error.__class__.__name__)
                    sys.exit(1)
                else:
                    logging.warning("The given deployment has no HTTPD FQDN "
                                    "content")

        return httpd_fqdn

    def get_enm_sed_params(self, sed_param):
        """
        :param sed_param: This is sed parameter for fetching the ip
        :return: The ip for a given sed_param
        """
        sed_info = self.get_enm_sed_content()
        try:
            ip_list_of_sed_params = \
                sed_info["parameter_defaults"][sed_param].split(',')
            ip_of_sed_params = ip_list_of_sed_params[0].strip()
            if not ip_of_sed_params:
                raise EmptySed
        except (KeyError, EmptySed):
            try:
                ip_list_of_sed_params = \
                    sed_info["parameters"][sed_param].split(',')
                ip_of_sed_params = ip_list_of_sed_params[0].strip()
                if not ip_of_sed_params:
                    raise EmptySed
            except (KeyError, EmptySed) as error:
                logging.error("Unable to find ip for " + sed_param)
                logging.error(error.__class__.__name__)
                sys.exit(1)

        return ip_of_sed_params

    def get_vnflcm_sed_params(self, sed_param):
        """
        :param sed_param: This is sed parameter for which fetching the ip
        :return: The ip for a given sed_param
        """
        sed_info = self.get_vnflcm_sed_content()
        try:
            ip_list_of_sed_params = \
                sed_info["parameter_defaults"][sed_param].split(',')
            ip_of_sed_params = ip_list_of_sed_params[0].strip()
            if not ip_of_sed_params:
                raise EmptySed
        except (KeyError, EmptySed):
            try:
                ip_list_of_sed_params = \
                    sed_info["parameters"][sed_param].split(',')
                ip_of_sed_params = ip_list_of_sed_params[0].strip()
                if not ip_of_sed_params:
                    raise EmptySed
            except (KeyError, EmptySed) as error:
                logging.error("Unable to find ip for " + sed_param)
                logging.error(error.__class__.__name__)
                sys.exit(1)

        return ip_of_sed_params

    def get_private_key(self):
        """
        :return: returns private key for a given deployment
        """
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/deployments/",
            query="?q=name=" + self.deployment_id,
            field="enm"
        )
        logging.debug(str(deployment_json))
        try:
            private_key = deployment_json[0]["enm"]["private_key"]
            return private_key
        except KeyError as error:
            logging.error("Unable to find private key")
            logging.error(error.__class__.__name__)
            sys.exit(1)

    def get_cloud_native_document(self):
        """
        :return: True or False depending if the environment has a cloud native document
        """
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/deployments/",
            query="?q=name=" + self.deployment_id,
            field="documents"
        )
        logging.debug(str(deployment_json))
        try:
            documents = deployment_json[0]['documents']
            for document in documents:
                if document["schema_name"] == "cloud_native_enm":
                    return True
            return False
        except KeyError as error:
            logging.warning("Unable to find cloud_native_enm document")
            logging.warning(error.__class__.__name__)
            return False

    def get_netsim_content(self):
        """
        :return: returns a list of netsims associated with the given deployment
        """
        netsims = []
        netsim_id = self.get_document_id("netsim")
        deployment_json = self.run_dit_rest_call(
            deployment_detail="/api/documents/",
            query=netsim_id,
            field="content"
        )
        logging.debug(str(deployment_json))
        try:
            if not netsim_id:
                raise NetsimsNotFound
            vms = deployment_json["content"]["vm"]
            for vm in vms:
                if vm["active"]:
                    netsims.append(vm["hostname"])
                    print vm["hostname"]
            if not len(netsims):
                raise NetsimsNotFound
            return netsims
        except KeyError as error:
            logging.error("Unable to find netsim content from DIT JSON "
                          "response")
            logging.error(error.__class__.__name__)
            sys.exit(1)
        except NetsimsNotFound:
            logging.error("Unable to find netsim vms for the given deployment")
            sys.exit(1)

    @staticmethod
    def run_dit_rest_call(**kwargs):
        """
        Run REST call towards the DIT and return the result of the GET request
        :return JSON response from GET request
        """
        deployment_detail = kwargs.pop('deployment_detail')
        query = kwargs.pop('query')
        field = kwargs.pop('field')
        if kwargs:
            raise TypeError('Unexpected **kwargs: %r' % kwargs)

        base_dit_url = CONFIG.get("MT_Cloud", "dit_url")
        rest_url = base_dit_url + deployment_detail
        if query:
            rest_url = rest_url + query

        if field in ["project_id", "documents", "enm"]:
            rest_url = rest_url + "&fields=" + field
        elif field:
            rest_url = rest_url + "?fields=" + field

        response = common_functions.return_url_response(rest_url)
        json_response = common_functions.return_json_object(response)
        if json_response:
            return json_response
        else:
            logging.error("Blank JSON response")
            sys.exit(1)


def parse_args():
    """
    :return parser.parse_args():
    This function parses the passed in system arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    Description:
    ------------
    This will retrieve deployment information based on deployment name.
    Pass in the flag for what you want to search for plus
    the name of the deployment.

    For multiple items to search,
    you must enter the deployment name for each one

    Examples:
    ------------
    ''' + sys.argv[0] + ''' --deployment_type -c ieatenmpca05
    ''' + sys.argv[0] + ''' --dmt_id -c ieatenmpca05
    ''' + sys.argv[0] + ''' --username --password -c ieatenmpca05
    --auth_url
    ''',
        epilog=''''''
    )
    parser.add_argument("-c", "--cluster_id",
                        help="Cluster Id of the deployment", required=True)
    parser.add_argument("-t", "--deployment_type", nargs='?', default='cloud',
                        help="Type of the deployment")
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    parser.add_argument("-i", "--dmt_id",
                        help="Return the DMT cluster ID "
                             "for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-a", "--auth_url",
                        help="Return the auth_url for a given deployment name",
                        nargs='?', const=True)
    parser.add_argument("-s", "--sed_file_location",
                        help="Return the SED File location "
                             "for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-u", "--username",
                        help="Return the username "
                             "for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-p", "--password",
                        help="Return the password "
                             "for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-n", "--project_name",
                        help="Return the project name"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-b", "--dashboard",
                        help="Return the dashboard IP"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-l", "--workload_vm_hostname",
                        help="Return the workload VM hostname"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-w", "--workload_vm_ip",
                        help="Return workload VM IP"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-di", "--director_vm_ip",
                        help="Return director VM IP"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-dn", "--director_vm_namespace",
                        help="Return the cENM namespace"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-y", "--sed_content",
                        help="Return SED content"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-f", "--httpd_fqdn",
                        help="Return HTTPD FQDN"
                             " for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-e", "--pem_file_location",
                        help="Return the PEM File location "
                             "for a given deployment name", nargs='?',
                        const=True)
    parser.add_argument("-r", "--print_to_screen",
                        help="Option to print the value to screen", nargs='?',
                        const=True)
    parser.add_argument("-d", "--netsim_servers",
                        help="Returns the netsim servers for a given "
                             "deployment name ", nargs='?', const=True)
    parser.add_argument("-k", "--private_key",
                        help="Returns the private key for a given "
                             "deployment name ", nargs='?', const=True)
    parser.add_argument("-iv", "--ignore_validation",
                        help="Option to ignore validation of workload IP or "
                             "workload hostname", nargs='?',
                        const=True)
    parser.add_argument("-x", "--get_enm_sed_params",
                        help="Option to get ip of vm for "
                             "a given deployment")
    parser.add_argument("-g", "--get_vnflcm_sed_params",
                        help="Option to get vnf lcm document "
                             "information for a given deployment")
    parser.add_argument("-ha", "--get_vnflcm_sed_ha_status",
                        help="Option to get VNF LCM HA status "
                             "information for a given deployment", nargs='?',
                        const=True)
    parser.add_argument("-cn", "--cloud_native",
                        help="Identifier to know whether or not an environment "
                             "in DIT is cloud native based", nargs='?',
                        const=True)

    if len(sys.argv[1:]) == 0:
        logging.error("No arguments passed in")
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def get_cloud_deployment_details(dit, args):
    """
    :param dit: Instance of RetrieveFromDIT
    :param args: Parsed Arguments

    This function searches for vENM deployment details from DIT
    """

    if args.auth_url:
        auth_url = dit.get_pod_content("authUrl")
        logging.info("AUTH URL = " + auth_url)
        common_functions.print_to_screen(auth_url, args.print_to_screen)

    if args.sed_file_location:
        logging.info("Please check DIT for sed version")

    if args.username:
        username = dit.get_project_content("username")
        logging.info("Project username = " + username)
        common_functions.print_to_screen(username, args.print_to_screen)

    if args.password:
        password = dit.get_project_content("password")
        logging.info("Project password = " + password)
        common_functions.print_to_screen(password, args.print_to_screen)

    if args.project_name:
        project_name = dit.get_project_content("name")
        logging.info("Project name = " + project_name)
        common_functions.print_to_screen(project_name, args.print_to_screen)

    if args.workload_vm_hostname:
        workload_vm_hostname = dit.get_workload_content("hostname",
                                                        args.ignore_validation)
        logging.info("Workload VM Hostname = " + workload_vm_hostname)
        common_functions.print_to_screen(workload_vm_hostname,
                                         args.print_to_screen)

    if args.workload_vm_ip:
        workload_vm_ip = dit.get_workload_content("ip", args.ignore_validation)
        logging.info("Workload VM IP = " + str(workload_vm_ip))
        common_functions.print_to_screen(workload_vm_ip, args.print_to_screen)

    if args.director_vm_namespace:
        director_vm_namespace = dit.get_director_content("hostname",
                                                        args.ignore_validation)
        logging.info("Director Namespace = " + director_vm_namespace)
        common_functions.print_to_screen(director_vm_namespace,
                                         args.print_to_screen)

    if args.director_vm_ip:
        director_vm_ip = dit.get_director_content("ip", args.ignore_validation)
        logging.info("Director IP = " + str(director_vm_ip))
        common_functions.print_to_screen(director_vm_ip, args.print_to_screen)


    if args.sed_content:
        sed_content = dit.get_enm_sed_content(args.ignore_validation)
        common_functions.print_to_screen(
            json.dumps(sed_content), args.print_to_screen)

    if args.httpd_fqdn:
        httpd_fqdn = dit.get_httpd_fqdn_content(args.ignore_validation)
        common_functions.print_to_screen(httpd_fqdn,
                                         args.print_to_screen)
    if args.pem_file_location:
        logging.info("Please check DIT for PEM key, or key pair stack")

    if args.private_key:
        private_key = dit.get_private_key()
        logging.debug("Private Key = " + str(private_key))
        common_functions.print_to_screen(private_key, args.print_to_screen)

    if args.netsim_servers:
        netsim_servers = dit.get_netsim_content()
        logging.info("Netsim Servers :" + str(netsim_servers))

    if args.get_enm_sed_params:
        ip_of_sed_params = dit.get_enm_sed_params(args.get_enm_sed_params)
        logging.info("Ip of " + args.get_enm_sed_params + " :" + str(
            ip_of_sed_params))
        common_functions.print_to_screen(ip_of_sed_params,
                                         args.print_to_screen)

    if args.get_vnflcm_sed_params:
        ip_of_sed_params = \
            dit.get_vnflcm_sed_params(args.get_vnflcm_sed_params)
        logging.info("Ip of " + args.get_vnflcm_sed_params + " :" + str(
            ip_of_sed_params))
        common_functions.print_to_screen(ip_of_sed_params,
                                         args.print_to_screen)

    if args.get_vnflcm_sed_ha_status:
        ha_status = dit.get_vnflcm_sed_ha_status()
        logging.info("HA status of " + args.cluster_id + " :" + str(
            ha_status))
        common_functions.print_to_screen(ha_status,
                                         args.print_to_screen)

    if args.cloud_native:
        is_environment_cloud_native = dit.get_cloud_native_document()
        logging.info("Is environment cloud native: " + str(is_environment_cloud_native))
        common_functions.print_to_screen(is_environment_cloud_native,
                                         args.print_to_screen)


def execute_functions(args):
    """
    This function executes the script tasks and functions based on the
    arguments passed in
    """
    common_functions.determine_logging_level(args.verbose)
    if args.deployment_type == "cloud":
        search_dit = RetrieveFromDIT(args.cluster_id)
        get_cloud_deployment_details(search_dit, args)
    else:
        logging.error("Invalid deployment type provided " + str(
            args.deployment_type))
        sys.exit(1)


if __name__ == "__main__":
    config.init(__file__)
    execute_functions(parse_args())
