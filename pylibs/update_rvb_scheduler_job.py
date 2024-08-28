"""
This script is used to update the list of cluster_ids (scheduled environments) for the RVB STKPI
scheduler job
"""
import sys
import logging
import argparse
import re
import requests
import xml.etree.ElementTree as elementTree
import configuration

import common_functions

requests.packages.urllib3.disable_warnings()

CONFIG = configuration.UtilsConfig()
THUNDERBEE_USER = CONFIG.get("COMMON_VARIABLES", "thunderbee_functional_user")


class UpdateRvbSchedulerJob:
    """Updates the cluster_id parameter in a RVB scheduler job"""

    def __init__(self, cluster_id, scheduler_job, fem):
        self.thunderbee_api = CONFIG.get(
            "COMMON_VARIABLES", "thunderbee_functional_user_api_token_of_{0}".format(fem))
        self.scheduler_job = scheduler_job
        self.rvb_scheduler_url = CONFIG.get("COMMON_VARIABLES",
                                            "rvb_{0}_url_{1}"
                                            .format(self.scheduler_job.lower(),
                                                    fem))
        self.cluster_id = cluster_id
        self.new_cluster_ids = None
        self.original_cluster_ids = self.scheduled_environments

    @property
    def rvb_scheduler_job_as_json(self):
        """
        Get the RVB scheduler job in json format.
        :return: scheduler_job:
        """
        url = '{0}/api/json'.format(self.rvb_scheduler_url)
        scheduler_job = requests.get(url, verify=False,
                                     auth=(THUNDERBEE_USER, self.thunderbee_api)).json()
        return scheduler_job

    @property
    def scheduled_environments(self):
        """
        Get all environments that are currently scheduled to run.
        :return: default_job_parameters:
        """
        scheduler_job = self.rvb_scheduler_job_as_json
        job_params = scheduler_job['actions'][1]['parameterDefinitions']
        for param in job_params:
            if param['name'] == 'cluster_ids':
                return param['defaultParameterValue']['value']

        logging.error('The parameter cluster_ids was not found in the job. Exiting...')
        sys.exit(1)

    def add_environment_to_scheduler(self):
        """
        Adds a new environment to the list of scheduled environments.
        """
        logging.info('Adding {0} to the scheduler: {1}'
                     .format(self.cluster_id, self.scheduler_job))
        if self.cluster_id in self.original_cluster_ids:
            logging.warn('Environment {0} is already scheduled to run. '
                         'Ignoring...'.format(self.cluster_id))
        else:
            self.new_cluster_ids = '{0},{1}'.format(self.original_cluster_ids, self.cluster_id)
            logging.info(('New parameter list is: {0}'.format(self.new_cluster_ids)))

    def remove_environment_from_scheduler(self):
        """
        Removes the environment from the list of scheduled environments.
        """
        logging.info('Removing {0} from the scheduler: {1}'
                     .format(self.cluster_id, self.scheduler_job))
        if self.cluster_id in self.original_cluster_ids:
            environments = self.original_cluster_ids.split(',')
            remaining_environments = [environment for environment in environments
                                      if environment != self.cluster_id]
            self.new_cluster_ids = ",".join(remaining_environments)
            logging.info(('New parameter list is: {0}'.format(self.new_cluster_ids)))
        else:
            logging.warn('Environment {0} is not in the list of scheduled '
                         'environments. Ignoring...'.format(self.cluster_id))

    def update_scheduler_cluster_ids(self):
        """
        This method updates the RVB scheduler job default parameters for cluster_ids.
        """
        scheduler_job_config_url = '{0}/config.xml'.format(self.rvb_scheduler_url)
        scheduler_job_config = requests.get(scheduler_job_config_url, verify=False,
                                            auth=(THUNDERBEE_USER, self.thunderbee_api)
                                            ).content

        scheduler_job_xml = elementTree.fromstring(scheduler_job_config)

        for scheduler_job_parameters in scheduler_job_xml.\
                iter('hudson.model.TextParameterDefinition'):
            for parameter_child in scheduler_job_parameters.iter('defaultValue'):
                if parameter_child.text:
                    if self.original_cluster_ids in parameter_child.text:
                        parameter_child.text = self.new_cluster_ids

        scheduler_job_xml_as_string = elementTree.tostring(scheduler_job_xml,
                                                           encoding='utf8',
                                                           method='xml')

        try:
            logging.info('Making request to update the job: {0}'.format(self.rvb_scheduler_url))
            requests.post(url=scheduler_job_config_url, data=scheduler_job_xml_as_string,
                          headers={'Content-Type': 'application/xml; charset=utf8'},
                          auth=(THUNDERBEE_USER, self.thunderbee_api))
            logging.info('RVB scheduler is now updated to run on the following cluster_ids: '
                         '{0}'.format(self.new_cluster_ids))
            logging.info('See scheduler job: {0}'.format(self.rvb_scheduler_url))
        except requests.exceptions.RequestException as bad_request:
            logging.error(bad_request)
            logging.error('Something went wrong updating the RVB scheduler job {0}. '
                          'Exiting...'.format(self.rvb_scheduler_url))
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
    This script will be used to update the environments for the RVB STKPI schedulers.
    ''',
        epilog='''
    Examples:
      -> ''' + sys.argv[0] + ''' -c 306 -u
      https://fem169-eiffel004.lmera.ericsson.se:8443/jenkins/job/
      update_rvb_scheduler_environments/1/ -a
      -j RAN_Core_Scheduler_Job
      -> ''' + sys.argv[0] + ''' -c 306 -u
      https://fem169-eiffel004.lmera.ericsson.se:8443/jenkins/job/
      update_rvb_scheduler_environments/1/ -r
      -j RAN_Core_Scheduler_Job,Transport_Scheduler_Job
    '''
    )
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity",
                        action="store_true")
    parser.add_argument("-c", "--cluster_id",
                        help="The environment to add to/remove from the "
                             "specified schedulers", required=True)
    parser.add_argument("-u", "--build_url",
                        help="The url of the job being built.", required=True)
    parser.add_argument("-s", "--schedulers_to_update",
                        help="A comma separated list of the scheduler job "
                             "names that will be changed.", required=True)
    parser.add_argument("-a", "--add",
                        help="Option to add an environment to the scheduler", nargs='?',
                        const=True)
    parser.add_argument("-r", "--remove",
                        help="Option to remove environment from the scheduler", nargs='?',
                        const=True)

    if not sys.argv:
        logging.error("No arguments passed in")
        parser.print_help()
        parser.exit()
    return parser.parse_args()


def update_rvb_scheduler_environments(args):
    """
    This function updates the list of scheduled RVB environments.
    It can either add or remove a environment.
    :param args:
    :return:
    """
    common_functions.determine_logging_level(args.verbose)

    cluster_id = args.cluster_id
    job_url = args.build_url
    schedulers_to_update = args.schedulers_to_update

    fem = re.split('//|-', job_url)[1]

    for scheduler_to_update in schedulers_to_update.split(','):
        rvb_scheduler = UpdateRvbSchedulerJob(cluster_id, scheduler_to_update,
                                              fem)

        if args.add:
            logging.info('You have selected to add the environment {0}'.format(cluster_id))
            rvb_scheduler.add_environment_to_scheduler()
        elif args.remove:
            logging.info('You have selected to remove the environment {0}'.format(cluster_id))
            rvb_scheduler.remove_environment_from_scheduler()
        else:
            logging.warning('You have not selected if you want to add or'
                            'remove an environment. Exiting...')
            sys.exit(1)

        if rvb_scheduler.new_cluster_ids:
            rvb_scheduler.update_scheduler_cluster_ids()


if __name__ == '__main__':
    update_rvb_scheduler_environments(parse_args())