"""Module to represent generic deployment infrastructure"""
import logging
import sys

from MTELoopScripts.etc.pylibs.lib.cifwk.dit import DIT
from MTELoopScripts.etc.pylibs.lib.deployment.sed import SED
from MTELoopScripts.etc.pylibs.lib.deployment.ddp import DDP

# DIT Keys
DOC_ID = "document_id"
DEP_DOCS = "documents"
ENM_KEY = "enm"
POD_ID = "pod_id"
PROJECT_ID = "project_id"
SCHEMA_NAME = "schema_name"
SED_ID = "sed_id"


class CloudDeployment(object):
    """This object represents an Openstack ENM Cloud Deployment"""

    _sed = None
    _ddp = None
    _enm_info = None
    _docs = None
    _dit = DIT()

    def __init__(self, deployment_name):
        """ Initialise the deployment info
        :param deployment_name: The DIT deployment name
        """

        self._deployment_name = deployment_name
        self._id = self._dit.get_deployment_id_from_name(deployment_name)

    @property
    def sed(self):
        if self._sed is None:
            enm_info = self._get_enm_info()
            self._sed = SED(enm_info[SED_ID])
        return self._sed

    @property
    def ddp(self):
        """The DDP information related to this deployment"""
        if self._ddp is None:
            ddp_document_id = self._get_doc_by_type("ddp")
            self._ddp = DDP(ddp_document_id)
        return self._ddp

    def _get_enm_info(self):
        """ Retrieves the enm specific information for a deployment
        :return: enm_info
        """
        if self._enm_info is None:
            self._enm_info = self._dit.get_deployment_content(self._id, ENM_KEY)
        return self._enm_info

    def _get_documents(self):
        """Get the deployment related documents
        :return: list of deployment docs
        """
        if self._docs is None:
            self._docs = self._dit.get_deployment_content(self._id, DEP_DOCS)
        return self._docs

    def _get_doc_by_type(self, doc_type):
        """Filters the deployment docs for a specific type
        :param doc_type: The doc type to lookup
        :return: The document
        """
        for doc in self._get_documents():
            if doc[SCHEMA_NAME] == doc_type:
                return doc[DOC_ID]
        logging.error(
            "Document with schema type {0} not associated with deployment".
            format(doc_type))
        sys.exit(1)