"""This module contains a wrapper around LASER for extended analysis
purposes."""

from mythril.analysis.module import EntryPoint, ModuleLoader, get_detection_module_hooks
from mythril.laser.execution_info import ExecutionInfo
from mythril.laser.ethereum import svm
from mythril.laser.ethereum.state.account import Account
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.strategy.basic import (
    BreadthFirstSearchStrategy,
    DepthFirstSearchStrategy,
    ReturnRandomNaivelyStrategy,
    SHSsStrategy,
    BasicSearchStrategy,
)

from mythril.laser.ethereum.natives import PRECOMPILE_COUNT
from mythril.laser.ethereum.transaction.symbolic import ACTORS


from mythril.laser.plugin.loader import LaserPluginLoader
from mythril.laser.plugin.plugins import (
    MutationPrunerBuilder,
    DependencyPrunerBuilder,
    CoveragePluginBuilder,
    CallDepthLimitBuilder,
    InstructionProfilerBuilder,
)
from mythril.laser.ethereum.strategy.extensions.bounded_loops import (
    BoundedLoopsStrategy,
)
from mythril.laser.smt import symbol_factory, BitVec
from mythril.support.support_args import args
from typing import Union, List, Type, Optional
from mythril.solidity.soliditycontract import EVMContract, SolidityContract
from .ops import Call, VarType, get_variable


class SymExecWrapper:
    """Wrapper class for the LASER Symbolic virtual machine.

    对代码进行符号执行并进行预分析
    """

    def __init__(
        self,
        contract,
        address: Union[int, str, BitVec],
        strategy: str,
        dynloader=None,#DynLoader()动态加载，用于获取链上存储数据和依赖项的动态加载程序逻辑
        max_depth: int = 22,
        execution_timeout: Optional[int] = None,
        loop_bound: int = 3,
        create_timeout: Optional[int] = None,
        transaction_count: int = 2,
        compulsory_statespace: bool = True,
        disable_dependency_pruning: bool = False,
        run_analysis_modules: bool = True,
    ):
     

        if isinstance(address, str):
            address = symbol_factory.BitVecVal(int(address, 16), 256)#使用z3,返回类型为BitVec的位向符号，值为0
        if isinstance(address, int):
            address = symbol_factory.BitVecVal(address, 256)
        
        if strategy == "dfs":
            s_strategy = DepthFirstSearchStrategy  # type: Type[BasicSearchStrategy]
        elif strategy == "bfs":
            s_strategy = BreadthFirstSearchStrategy
        elif strategy == "naive-random":
            s_strategy = ReturnRandomNaivelyStrategy
        elif strategy == "shs-s":
            s_strategy = SHSsStrategy
        else:
            raise ValueError("Invalid strategy argument supplied")
        #创建代表以太坊帐户的Account类。
        creator_account = Account(
            hex(ACTORS.creator.value), "", dynamic_loader=None, contract_name=None
        )#creator.value=0xAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE

        attacker_account = Account(
            hex(ACTORS.attacker.value), "", dynamic_loader=None, contract_name=None
        )

        if not contract.creation_code:
            self.accounts = {hex(ACTORS.attacker.value): attacker_account}
        else:
            self.accounts = {
                hex(ACTORS.creator.value): creator_account,
                hex(ACTORS.attacker.value): attacker_account,
            }


        requires_statespace = (
            compulsory_statespace
            or len(ModuleLoader().get_detection_modules(EntryPoint.POST)) > 0
        )#false
        
        #!!!符号执行引擎，创建符号虚拟机，挖掘控制流程图，获取符号执行数据并进行初步漏洞检测 
        self.laser = svm.LaserEVM(
            dynamic_loader=dynloader,
            max_depth=max_depth,
            execution_timeout=execution_timeout,
            strategy=s_strategy,#bfs
            create_timeout=create_timeout,
            transaction_count=transaction_count,#2
            requires_statespace=requires_statespace,#false
        )

        if loop_bound is not None:
            #将循环修剪添加到搜索策略中，如果目标是以JUMPDEST限制次数为目标，则忽略JUMPI指令 ！！
            self.laser.extend_strategy(BoundedLoopsStrategy, loop_bound)

        plugin_loader = LaserPluginLoader()#与插件相关的加载逻辑
        plugin_loader.load(CoveragePluginBuilder())#测量指令覆盖率，覆盖率是已执行指令与指令的总量的比率 ?？只initial该插件，根据hook点进行？？
        plugin_loader.load(MutationPrunerBuilder())#优化抑制了由“clean”行为引起的路径爆炸
        plugin_loader.load(CallDepthLimitBuilder())
        

        plugin_loader.add_args(
            "call-depth-limit", call_depth_limit=args.call_depth_limit
        )

        if not disable_dependency_pruning:
            plugin_loader.load(DependencyPrunerBuilder())#插件在包含该块的执行路径中保存一个访问（读取）的存储位置列表

        plugin_loader.instrument_virtual_machine(self.laser, None)#创建evm虚拟机并将启用的插件加载到符号虚拟机中

        world_state = WorldState()#WorldState类 表示黄皮书中描述的世界状态，包括合约账户创建等
        for account in self.accounts.values():
            world_state.put_account(account)

        if run_analysis_modules:
            #获得所有合约漏洞检测模块
            analysis_modules = ModuleLoader().get_detection_modules(
                EntryPoint.CALLBACK
            )
            #定义entrypoint字典，对每个opcode设置需要进行hooks插桩点pre_hook,post_hook
            self.laser.register_hooks(
                hook_type="pre",
                hook_dict=get_detection_module_hooks(analysis_modules, hook_type="pre"),
            )
            self.laser.register_hooks(
                hook_type="post",
                hook_dict=get_detection_module_hooks(
                    analysis_modules, hook_type="post"
                ),
            )

        if isinstance(contract, SolidityContract):
            self.laser.sym_exec(
                creation_code=contract.creation_code,
                contract_name=contract.name,
                world_state=world_state,
            )#运行符号执行
        elif isinstance(contract, EVMContract) and contract.creation_code:
            self.laser.sym_exec(
                creation_code=contract.creation_code,
                contract_name=contract.name,
                world_state=world_state,
            )
        else:#如果仅提供智能合约地址时.添加地址对应合约账户进行检测
            account = Account(
                address,
                contract.disassembly,
                dynamic_loader=dynloader,
                contract_name=contract.name,
                balances=world_state.balances,
                concrete_storage=True
                if (dynloader is not None and dynloader.active)
                else False,
            )

            if dynloader is not None:
                if isinstance(address, int):
                    try:
                        _balance = dynloader.read_balance(
                            "{0:#0{1}x}".format(address, 42)
                        )
                        account.set_balance(_balance)
                    except:
                        # Initial balance will be a symbolic variable
                        pass
                elif isinstance(address, str):
                    try:
                        _balance = dynloader.read_balance(address)
                        account.set_balance(_balance)
                    except:
                        # Initial balance will be a symbolic variable
                        pass
                elif isinstance(address, BitVec):
                    try:
                        _balance = dynloader.read_balance(
                            "{0:#0{1}x}".format(address.value, 42)
                        )
                        account.set_balance(_balance)
                    except:
                        # Initial balance will be a symbolic variable
                        pass
            
            world_state.put_account(account)
            self.laser.sym_exec(world_state=world_state, target_address=address.value)

        if not requires_statespace:
            return


        self.nodes = self.laser.nodes
        self.edges = self.laser.edges


        # 分析调用以使其易于访问

        self.calls = []  # type: List[Call]

        for key in self.nodes:

            state_index = 0

            for state in self.nodes[key].states:

                instruction = state.get_current_instruction()

                op = instruction["opcode"]

                if op in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):

                    stack = state.mstate.stack

                    if op in ("CALL", "CALLCODE"):
                        gas, to, value, meminstart, meminsz, memoutstart, memoutsz = (
                            get_variable(stack[-1]),
                            get_variable(stack[-2]),
                            get_variable(stack[-3]),
                            get_variable(stack[-4]),
                            get_variable(stack[-5]),
                            get_variable(stack[-6]),
                            get_variable(stack[-7]),
                        )

                        if (
                            to.type == VarType.CONCRETE
                            and 0 < to.val <= PRECOMPILE_COUNT
                        ):
                            # ignore prebuilts
                            continue

                        if (
                            meminstart.type == VarType.CONCRETE
                            and meminsz.type == VarType.CONCRETE
                        ):
                            self.calls.append(
                                Call(
                                    self.nodes[key],
                                    state,
                                    state_index,
                                    op,
                                    to,
                                    gas,
                                    value,
                                    state.mstate.memory[
                                        meminstart.val : meminsz.val + meminstart.val
                                    ],
                                )
                            )
                        else:
                            self.calls.append(
                                Call(
                                    self.nodes[key],
                                    state,
                                    state_index,
                                    op,
                                    to,
                                    gas,
                                    value,
                                )
                            )
                    else:
                        gas, to, meminstart, meminsz, memoutstart, memoutsz = (
                            get_variable(stack[-1]),
                            get_variable(stack[-2]),
                            get_variable(stack[-3]),
                            get_variable(stack[-4]),
                            get_variable(stack[-5]),
                            get_variable(stack[-6]),
                        )

                        self.calls.append(
                            Call(self.nodes[key], state, state_index, op, to, gas)
                        )

                state_index += 1

    @property
    def execution_info(self) -> List[ExecutionInfo]:
        return self.laser.execution_info
