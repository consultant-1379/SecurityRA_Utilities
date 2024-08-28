#!/usr/bin/env python
""" config.py - Does the basic Configuration needed for all the commandline
    python scripts
    Creates the log folder in /../logs/
"""
import logging

# pylint: disable=invalid-name

# Get the Root Logger and Set the Handlers and the Formatters
logger = logging.getLogger('')
if not len(logger.handlers):
    logger.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(levelname)s][%(filename)s:%(funcName)s:%(lineno)s][%(asctime)s] '
        '%(message)s')
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)
    logger.addHandler(console)


def init(filename):
    """
    as part of https://jira-nam.lmera.ericsson.se/browse/RTD-1307 this
    function to be updated with new system of python script logging. Dummy
    function used for now to save major amendments to python scripts.
    """

    dummy_val = filename