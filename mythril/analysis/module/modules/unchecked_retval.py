"""This module contains detection code to find occurrences of calls whose
return value remains unchecked."""
from copy import copy
from typing import cast, List, Union, Mapping

from mythril.analysis import solver
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import UNCHECKED_RET_VAL
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.exceptions import UnsatError
from mythril.laser.smt.bitvec import BitVec

from mythril.laser.ethereum.state.annotation import StateAnnotation
from mythril.laser.ethereum.state.global_state import GlobalState

import logging

log = logging.getLogger(__name__)


class UncheckedRetvalAnnotation(StateAnnotation):
    def __init__(self) -> None:
        self.retvals = []  # type: List[Mapping[str, Union[int, BitVec]]]

    def __copy__(self):
        result = UncheckedRetvalAnnotation()
        result.retvals = copy(self.retvals)
        return result


class UncheckedRetval(DetectionModule):
    """A detection module to test whether CALL return value is checked."""

    name = "Return value of an external call is not checked"
    swc_id = UNCHECKED_RET_VAL
    description = (
        "Test whether CALL return value is checked. "
        "For direct calls, the Solidity compiler auto-generates this check. E.g.:\n"
        "    Alice c = Alice(address);\n"
        "    c.ping(42);\n"
        "Here the CALL will be followed by IZSERO(retval), if retval = ZERO then state is reverted. "
        "For low-level-calls this check is omitted. E.g.:\n"
        '    c.call.value(0)(bytes4(sha3("ping(uint256)")),1);'
    )
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["STOP", "RETURN"]
    post_hooks = ["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"]

    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """
        if state.get_current_instruction()["address"] in self.cache:
            return
        issues = self._analyze_state(state)
        for issue in issues:
            self.cache.add(issue.address)
        self.issues.extend(issues)

    def _analyze_state(self, state: GlobalState) -> list:
        instruction = state.get_current_instruction()

        annotations = cast(
            List[UncheckedRetvalAnnotation],
            [a for a in state.get_annotations(UncheckedRetvalAnnotation)],
        )
        if len(annotations) == 0:
            state.annotate(UncheckedRetvalAnnotation())
            annotations = cast(
                List[UncheckedRetvalAnnotation],
                [a for a in state.get_annotations(UncheckedRetvalAnnotation)],
            )

        retvals = annotations[0].retvals

        if instruction["opcode"] in ("STOP", "RETURN"):
            issues = []
            for retval in retvals:
                try:
                    """
                    To check whether retval is unconstrained we are checking it against retval = 0 and retval = 1
                    """
                    solver.get_transaction_sequence(
                        state, state.world_state.constraints + [retval["retval"] == 1]
                    )
                    transaction_sequence = solver.get_transaction_sequence(
                        state, state.world_state.constraints + [retval["retval"] == 0]
                    )
                except UnsatError:
                    continue

                description_tail = (
                    "  当合约使用了某些不安全的函数，调用失败时并不会引发异常，而是通过返回布尔值来标识执行状态\n，合约执行也将继续。当调用意外失败或攻击者强制调用失败时，可能会导致后续程序逻辑出现意外行为。"
                )
                solutions=["1)合约编写时尽量使用如tranfer()等安全函数，即使发生异常也会执行状态回滚;","2)若需要使用不安全的函数时，必须检查其返回值，对异常进行处理。"]

                issue = Issue(
                    contract=state.environment.active_account.contract_name,
                    function_name=state.environment.active_function_name,
                    address=retval["address"],
                    bytecode=state.environment.code.bytecode,
                    title="未检查返回值漏洞",
                    swc_id=UNCHECKED_RET_VAL,
                    severity="Medium",
                    description_head="  没有检查消息调用的返回值。",
                    description_tail=description_tail,
                    gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                    transaction_sequence=transaction_sequence,
                    solutions=solutions,
                )

                issues.append(issue)

            return issues
        else:
            log.debug("End of call, extracting retval")
            assert state.environment.code.instruction_list[state.mstate.pc - 1][
                "opcode"
            ] in ["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"]
            return_value = state.mstate.stack[-1]
            retvals.append(
                {"address": state.instruction["address"] - 1, "retval": return_value}
            )

        return []


detector = UncheckedRetval()
