"""This module provides classes that make up an issue report."""
import logging
import json
import operator
from jinja2 import PackageLoader, Environment
from typing import Dict, List, Any, Optional
import hashlib

from mythril.laser.execution_info import ExecutionInfo
from mythril.solidity.soliditycontract import SolidityContract
from mythril.analysis.swc_data import SWC_TO_TITLE
from mythril.support.source_support import Source
from mythril.support.start_time import StartTime
from mythril.support.support_utils import get_code_hash
from mythril.support.signatures import SignatureDB
from time import time

log = logging.getLogger(__name__)


class Issue:
    """Representation of an issue and its location."""

    def __init__(
        self,
        contract,
        function_name,
        address,
        swc_id,
        title,
        bytecode,
        gas_used=(None, None),
        severity=None,
        description_head="",
        description_tail="",
        transaction_sequence=None,
        solutions="",
    ):
        """

        :param contract: The contract
        :param function_name: Function name where the issue is detected
        :param address: The address of the issue
        :param swc_id: Issue's corresponding swc-id
        :param title: Title
        :param bytecode: bytecode of the issue
        :param gas_used: amount of gas used
        :param severity: The severity of the issue
        :param description_head: The top part of description
        :param description_tail: The bottom part of the description
        :param debug: The transaction sequence
        """
        self.title = title
        self.contract = contract
        self.function = function_name
        self.address = address
        self.description_head = description_head
        self.description_tail = description_tail
        self.description = "%s\n%s" % (description_head, description_tail)
        self.solutions= solutions
        self.severity = severity
        self.swc_id = swc_id
        self.min_gas_used, self.max_gas_used = gas_used
        self.filename = None
        self.code = None
        self.lineno = None
        self.source_mapping = None
        self.discovery_time = time() - StartTime().global_start_time
        self.bytecode_hash = get_code_hash(bytecode)
        self.transaction_sequence = transaction_sequence

    @property
    def transaction_sequence_users(self):
        """ Returns the transaction sequence without pre-generated block data"""
        return self.transaction_sequence

    @property
    def transaction_sequence_jsonv2(self):
        """ Returns the transaction sequence as a json string with pre-generated block data"""
        return (
            self.add_block_data(self.transaction_sequence)
            if self.transaction_sequence
            else None
        )

    @staticmethod
    def add_block_data(transaction_sequence: Dict):
        """ Adds sane block data to a transaction_sequence """
        for step in transaction_sequence["steps"]:
            step["gasLimit"] = "0x7d000"
            step["gasPrice"] = "0x773594000"
            step["blockCoinbase"] = "0xcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb"
            step["blockDifficulty"] = "0xa7d7343662e26"
            step["blockGasLimit"] = "0x7d0000"
            step["blockNumber"] = "0x66e393"
            step["blockTime"] = "0x5bfa4639"
        return transaction_sequence

    @property
    def as_dict(self):
        """

        :return:
        """

        issue = {
            "title": self.title,
            "swc-id": self.swc_id,
            "contract": self.contract,
            "description": self.description,
            "function": self.function,
            "severity": self.severity,
            "address": self.address,
            "solutions":self.solutions,
            "tx_sequence": self.transaction_sequence,
            "min_gas_used": self.min_gas_used,
            "max_gas_used": self.max_gas_used,
            "sourceMap": self.source_mapping,
        }

        if self.filename and self.lineno:
            issue["filename"] = self.filename
            issue["lineno"] = self.lineno

        if self.code:
            issue["code"] = self.code

        return issue

    def _set_internal_compiler_error(self):
        """
        Adds the false positive to description and changes severity to low
        """
        self.severity = "Low"
        self.description_tail += (
            " This issue is reported for internal compiler generated code."
        )
        self.description = "%s\n%s" % (self.description_head, self.description_tail)
        self.code = ""

    def add_code_info(self, contract):
        """

        :param contract:
        """
        if self.address and isinstance(contract, SolidityContract):
            codeinfo = contract.get_source_info(
                self.address, constructor=(self.function == "constructor")
            )
            self.filename = codeinfo.filename
            self.code = codeinfo.code
            self.lineno = codeinfo.lineno
            if self.lineno is None:
                self._set_internal_compiler_error()
            self.source_mapping = codeinfo.solc_mapping
        else:
            self.source_mapping = self.address

    def resolve_function_names(self):
        """ Resolves function names for each step """

        if (
            self.transaction_sequence is None
            or "steps" not in self.transaction_sequence
        ):
            return

        signatures = SignatureDB()

        for step in self.transaction_sequence["steps"]:
            _hash = step["input"][:10]

            try:
                sig = signatures.get(_hash)

                if len(sig) > 0:
                    step["name"] = sig[0]
                else:
                    step["name"] = "unknown"
            except ValueError:
                step["name"] = "unknown"


class Report:
    """A report containing the content of multiple issues."""

    environment = Environment(
        loader=PackageLoader("mythril.analysis"), trim_blocks=True
    )#加载jinja2模版环境，mythril/analysis/

    def __init__(
        self,
        contracts=None,
        exceptions=None,
        execution_info: Optional[List[ExecutionInfo]] = None,
    ):
        """

        :param contracts:
        :param exceptions:
        """
        self.issues = {}  # type: Dict[bytes, Issue]
        self.solc_version = ""
        self.meta = {}  # type: Dict[str, Any]
        self.source = Source()
        self.source.get_source_from_contracts_list(contracts)
        self.exceptions = exceptions or []
        self.execution_info = execution_info or []

    def sorted_issues(self):
        """

        :return:
        """
        issue_list = [issue.as_dict for key, issue in self.issues.items()]
        return sorted(issue_list, key=operator.itemgetter("address", "title"))

    def append_issue(self, issue):
        """

        :param issue:
        """
        m = hashlib.md5()##获取一个md5加密算法对象
        m.update((issue.contract + str(issue.address) + issue.title).encode("utf-8"))##制定需要加密的字符串
        issue.resolve_function_names()
        self.issues[m.digest()] = issue

    def as_text(self):
        """

        :return:
        """
        name = self._file_name()
        template = Report.environment.get_template("report_as_text.jinja2")

        return template.render(filename=name, issues=self.sorted_issues())

    def as_json(self):
        """

        :return:
        """
        result = {"success": True, "error": None, "issues": self.sorted_issues()}
        return json.dumps(result, sort_keys=True)

    def _get_exception_data(self) -> dict:
        if not self.exceptions:
            return {}
        logs = []  # type: List[Dict]
        for exception in self.exceptions:
            logs += [{"level": "error", "hidden": True, "msg": exception}]
        return {"logs": logs}

    def _file_name(self):
        """

        :return:
        """
        if len(self.issues.values()) > 0:
            return list(self.issues.values())[0].filename