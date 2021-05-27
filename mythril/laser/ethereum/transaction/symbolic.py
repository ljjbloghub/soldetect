"""This module contains functions setting up and executing transactions with
symbolic values."""
import logging
from typing import Optional

from mythril.disassembler.disassembly import Disassembly
from mythril.laser.ethereum.cfg import Node, Edge, JumpType
from mythril.laser.ethereum.state.account import Account
from mythril.laser.ethereum.state.calldata import SymbolicCalldata
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.transaction.transaction_models import (
    MessageCallTransaction,
    ContractCreationTransaction,
    get_next_transaction_id,
    BaseTransaction,
)
from mythril.laser.smt import symbol_factory, Or, BitVec

log = logging.getLogger(__name__)


class Actors:
    def __init__(
        self,
        creator=0xAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE,
        attacker=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF,
        someguy=0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
    ):
        self.addresses = {
            "CREATOR": symbol_factory.BitVecVal(creator, 256),
            "ATTACKER": symbol_factory.BitVecVal(attacker, 256),
            "SOMEGUY": symbol_factory.BitVecVal(someguy, 256),
        }

    def __setitem__(self, actor: str, address: Optional[str]):
        """
        Sets an actor to a desired address

        :param actor: Name of the actor to set
        :param address: Address to set the actor to. None to delete the actor
        """
        if address is None:
            if actor in ("CREATOR", "ATTACKER"):
                raise ValueError("Can't delete creator or attacker address")
            del self.addresses[actor]
        else:
            if address[0:2] != "0x":
                raise ValueError("Actor address not in valid format")

            self.addresses[actor] = symbol_factory.BitVecVal(int(address[2:], 16), 256)

    def __getitem__(self, actor: str):
        return self.addresses[actor]

    @property
    def creator(self):
        return self.addresses["CREATOR"]

    @property
    def attacker(self):
        return self.addresses["ATTACKER"]

    def __len__(self):
        return len(self.addresses)


ACTORS = Actors()


def execute_message_call(laser_evm, callee_address: BitVec) -> None:
    """Executes a message call transaction from all open states.

    :param laser_evm:
    :param callee_address:
    """
    # TODO: Resolve circular import between .transaction and ..svm to import LaserEVM here
    open_states = laser_evm.open_states[:]
    del laser_evm.open_states[:]

    for open_world_state in open_states:
        if open_world_state[callee_address].deleted:
            log.debug("Can not execute dead contract, skipping.")
            continue

        next_transaction_id = get_next_transaction_id()

        external_sender = symbol_factory.BitVecSym(
            "sender_{}".format(next_transaction_id), 256
        )

        transaction = MessageCallTransaction(
            world_state=open_world_state,
            identifier=next_transaction_id,
            gas_price=symbol_factory.BitVecSym(
                "gas_price{}".format(next_transaction_id), 256
            ),
            gas_limit=8000000,  # block gas limit
            origin=external_sender,
            caller=external_sender,
            callee_account=open_world_state[callee_address],
            call_data=SymbolicCalldata(next_transaction_id),
            call_value=symbol_factory.BitVecSym(
                "call_value{}".format(next_transaction_id), 256
            ),
        )
        _setup_global_state_for_execution(laser_evm, transaction)

    laser_evm.exec()


def execute_contract_creation(
    laser_evm, contract_initialization_code, contract_name=None, world_state=None
) -> Account:
    """根据creation_code，及open state，设置全局状态和cfg.执行合约部署交易操作，返回account类

    :param laser_evm:#LaserEVM类
    :param contract_initialization_code:
    :param contract_name:
    :return:
    """
    # TODO: Resolve circular import between .transaction and ..svm to import LaserEVM here
    del laser_evm.open_states[:]

    world_state = world_state or WorldState()
    open_states = [world_state]
    new_account = None
    for open_world_state in open_states:
        next_transaction_id = get_next_transaction_id()#1,每执行一次 id+1
        #对合约部署Transaction进行建模
        transaction = ContractCreationTransaction(
            world_state=open_world_state,#WorldState类
            identifier=next_transaction_id,
            gas_price=symbol_factory.BitVecSym(
                "gas_price{}".format(next_transaction_id), 256
            ),#z3 创建gas_price1的变量
            gas_limit=8000000,  # block gas limit
            origin=ACTORS["CREATOR"],
            code=Disassembly(contract_initialization_code),#creation_code
            caller=ACTORS["CREATOR"],
            contract_name=contract_name,
            call_data=None,
            call_value=symbol_factory.BitVecSym(
                "call_value{}".format(next_transaction_id), 256
            ),#z3设置 256位向量变量call_value1
        )
        #根据当前执行环境 为交易执行设置全局状态和cfg(控制流图)
        _setup_global_state_for_execution(laser_evm, transaction)
        new_account = new_account or transaction.callee_account#返回Account类 代表以太坊账户

    laser_evm.exec(True)

    return new_account


def _setup_global_state_for_execution(laser_evm, transaction: BaseTransaction) -> None:
    """为交易执行设置全局状态和cfg
    Sets up global state and cfg for a transactions execution.

    :param laser_evm:
    :param transaction:
    """
    # TODO: Resolve circular import between .transaction and ..svm to import LaserEVM here
    global_state = transaction.initial_global_state()#初始全局变量，包括WorldState类，balances,sender..返回GlobalState类
    global_state.transaction_stack.append((transaction, None))#合约事务堆栈

    global_state.world_state.constraints.append(
        Or(*[transaction.caller == actor for actor in ACTORS.addresses.values()])
    )#求解器添加约束，保证合约调用者与合约创建者一致

    new_node = Node(
        global_state.environment.active_account.contract_name,
        function_name=global_state.environment.active_function_name,#fallback和constructor
    )#表示流程图的节点

    #laser_evm.requires_statespace=false
    if laser_evm.requires_statespace:
        laser_evm.nodes[new_node.uid] = new_node


    if transaction.world_state.node:
        if laser_evm.requires_statespace:
            laser_evm.edges.append(
                Edge(
                    transaction.world_state.node.uid,#from
                    new_node.uid,#to
                    edge_type=JumpType.Transaction,
                    condition=None,
                )#添加边
            )
        new_node.constraints = global_state.world_state.constraints

    global_state.world_state.transaction_sequence.append(transaction)#增加交易序列
    global_state.node = new_node
    new_node.states.append(global_state)
    laser_evm.work_list.append(global_state)