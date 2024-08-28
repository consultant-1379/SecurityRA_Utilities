"""
 This script contains an object representation of an EMT deployment
"""


class EMTDeployment(object):
    """EMT Deployment Class object"""
    def __init__(self, data):
        self._emt_json = data

    def __eq__(self, other):
        """Overriding the = operator to compare deployment id's easier"""
        return self.id == other.id

    def __str__(self):
        """Overriding the __str__ operator to print a more elegant response"""
        return "EMTDeployment: " + self.name

    @property
    def id(self):  # pylint: disable-msg=C0103
        """Returns a deployments id value"""
        return self._emt_json["_id"]

    @property
    def name(self):
        """Returns a deployments name value"""
        return self._emt_json["name"]

    @property
    def state(self):
        """Returns a deployments state value"""
        return self._emt_json["state"]

    @property
    def test_phase(self):
        """Returns a deployments testPhase value"""
        return self._emt_json["testPhase"]

    @property
    def job_url(self):
        """Returns a deployments assignedJob value"""
        return self._emt_json["assignedJob"]

    @property
    def openstack_version(self):
        """Returns a deployments openstackVersion value"""
        return self._emt_json["openstackVersion"]