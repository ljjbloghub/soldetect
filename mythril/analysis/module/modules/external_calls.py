"""This module contains the detection code for potentially insecure low-level
calls."""

from mythril.analysis import solver
from mythril.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)
from mythril.analysis.swc_data import REENTRANCY
from mythril.laser.ethereum.state.constraints import Constraints
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.smt import UGT, symbol_factory, Or, BitVec
from mythril.laser.ethereum.natives import PRECOMPILE_COUNT
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.exceptions import UnsatError
from copy import copy
import logging

log = logging.getLogger(__name__)

DESCRIPTION = """

Search for external calls with unrestricted gas to a user-specified address.

"""


def _is_precompile_call(global_state: GlobalState):
    to = global_state.mstate.stack[-2]  # type: BitVec
    constraints = copy(global_state.world_state.constraints)
    constraints += [
        Or(
            to < symbol_factory.BitVecVal(1, 256),
            to > symbol_factory.BitVecVal(PRECOMPILE_COUNT, 256),
        )
    ]

    try:
        solver.get_model(constraints)
        return False
    except UnsatError:
        return True


class ExternalCalls(DetectionModule):
    """This module searches for low level calls (e.g. call.value()) that
    forward all gas to the callee."""

    name = "External call to another contract"
    swc_id = REENTRANCY
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["CALL"]

    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state: GlobalState):
        """

        :param state:
        :return:
        """
        gas = state.mstate.stack[-1]
        to = state.mstate.stack[-2]

        address = state.get_current_instruction()["address"]

        try:
            constraints = Constraints(
                [UGT(gas, symbol_factory.BitVecVal(2300, 256)), to == ACTORS.attacker]
            )

            solver.get_transaction_sequence(
                state, constraints + state.world_state.constraints
            )

            description_head = "  执行对用户提供的地址的调用导致的代码重入漏洞。"
            description_tail = (
                "  执行对调用者指定的地址的外部消息调用,被调用方帐户可能包含任意代码，并且可以重新输入任何函数\n,这可能导致函数间的调用以不被希望的方式进行交互。"
        
            )
            solutions=["1）在需要进行以太币交易时，使用transfer()或send()函数，此类函数只会使用2300个gas用于处理\n转币操作；",
           "2）在以太币被合约发送出去之前，对合约中的所有状态变量进行改变；",
           "3）保证在合约执行的时候引入互斥锁，保证状态变量不会被改变从而防止重入漏洞。",
            ]

            issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id=REENTRANCY,
                title="代码重入漏洞",
                bytecode=state.environment.code.bytecode,
                severity="Low",
                description_head=description_head,
                description_tail=description_tail,
                constraints=constraints,
                detector=self,
                solutions=solutions,
            )

        except UnsatError:
            log.debug("[EXTERNAL_CALLS] No model found.")
            return []

        return [issue]


detector = ExternalCalls()
