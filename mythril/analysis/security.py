"""This module contains functionality for hooking in detection modules and
executing them."""

from mythril.support.opcodes import opcodes
from mythril.analysis.module import ModuleLoader, reset_callback_modules
from mythril.analysis.module.base import EntryPoint
from mythril.analysis.report import Issue

from typing import Optional, List
import logging

log = logging.getLogger(__name__)


def retrieve_callback_issues() -> List[Issue]:
    """ Get the issues discovered by callback type detection modules"""
    issues = []  # type: List[Issue]
    for module in ModuleLoader().get_detection_modules(
        entry_point=EntryPoint.CALLBACK):
        issues += module.issues

    reset_callback_modules()

    return issues


def fire_lasers(statespace) -> List[Issue]:
    """ Fire lasers at analysed statespace object

    :param statespace: Symbolic statespace to analyze,SymExecWrapper
    """
    
    issues = []  

    for module in ModuleLoader().get_detection_modules(entry_point=EntryPoint.POST):
        log.info("Executing " + module.name)
        issues += module.execute(statespace)

    
    issues += retrieve_callback_issues()
    return issues
