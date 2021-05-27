#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import traceback
from typing import Optional, List

from . import MythrilDisassembler
from mythril.support.source_support import Source
from mythril.support.loader import DynLoader
from mythril.support.support_args import args
from mythril.analysis.symbolic import SymExecWrapper
from mythril.analysis.callgraph import generate_graph#生成控制流程图
from mythril.analysis.traceexplore import get_serializable_statespace
from mythril.analysis.security import fire_lasers, retrieve_callback_issues
from mythril.analysis.report import Report, Issue#报告输出
from mythril.ethereum.evmcontract import EVMContract
from mythril.laser.smt import SolverStatistics#smt求解器
from mythril.support.start_time import StartTime
from mythril.exceptions import DetectorNotFoundError
from mythril.laser.execution_info import ExecutionInfo

log = logging.getLogger(__name__)


class MythrilAnalyzer:
    """
    The Mythril Analyzer class
    Responsible for the analysis of the smart contracts
    """

    def __init__(
        self,
        disassembler: MythrilDisassembler,
        requires_dynld: bool = False,
        strategy: str = "dfs",
        address: Optional[str] = None,
        max_depth: Optional[int] = None,
        execution_timeout: Optional[int] = None,
        loop_bound: Optional[int] = None,
        create_timeout: Optional[int] = None,
        disable_dependency_pruning: bool = False,#是否进行依赖修剪
        custom_modules_directory: str = "",
        use_onchain_data: bool = True,
    ):
        """

        :param disassembler: The MythrilDisassembler class
        :param requires_dynld: whether dynamic loading should be done or not
        :param onchain_storage_access: Whether onchain access should be done or not
        """
        self.eth = disassembler.eth#none
        self.contracts = disassembler.contracts or []  # type: List[EVMContract]
        self.use_onchain_data = use_onchain_data
        self.strategy = strategy#bfs 广度优先
        self.address = address#0x0000..
        self.max_depth = max_depth#128
        self.execution_timeout = execution_timeout
        self.loop_bound = loop_bound#3 迭代次数
        self.create_timeout = create_timeout
        self.disable_dependency_pruning = disable_dependency_pruning#停止基于依赖的修剪 false
        self.custom_modules_directory = custom_modules_directory


    def fire_lasers(
        self,
        transaction_count: Optional[int] = None,
    ) -> Report:
        """
        :param modules: The analysis modules which should be executed
        :param transaction_count: The amount of transactions to be executed
        :return: The Report class which contains the all the issues/vulnerabilities
        """
        all_issues = []  # type: List[Issue]
        SolverStatistics().enabled = True
        exceptions = []
        execution_info = None  # type: Optional[List[ExecutionInfo]]
        for contract in self.contracts:
            StartTime()  # Reinitialize start time for new contracts
            try:

                sym = SymExecWrapper(
                    contract,
                    self.address,
                    self.strategy,#bfs
                    dynloader=DynLoader(self.eth, active=self.use_onchain_data),#动态加载，用于获取链上存储数据和依赖项的动态加载程序逻辑
                    max_depth=self.max_depth,
                    execution_timeout=self.execution_timeout,
                    loop_bound=self.loop_bound,#迭代循环边界 3
                    create_timeout=self.create_timeout,
                    transaction_count=transaction_count,
                    compulsory_statespace=False,
                    disable_dependency_pruning=self.disable_dependency_pruning,#false
                )#返回statespace
                
                
                issues = fire_lasers(sym)#analyze.security
               
                execution_info = sym.execution_info

            except DetectorNotFoundError as e:
                # Bubble up
                raise e
            except KeyboardInterrupt:
                log.critical("Keyboard Interrupt")
                issues = retrieve_callback_issues()
            except Exception:
                log.critical(
                    "Exception occurred, aborting analysis. Please report this issue to the Mythril GitHub page.\n"
                    + traceback.format_exc()
                )
                issues = retrieve_callback_issues()
                exceptions.append(traceback.format_exc())
                
            for issue in issues:
                issue.add_code_info(contract)

            all_issues += issues
            

 
        # Finally, output the results
        report = Report(
            contracts=self.contracts,
            exceptions=exceptions,
            execution_info=execution_info,
        )
        for issue in all_issues:
            report.append_issue(issue)

        return report

 
    def graph_html(
        self,
        contract: EVMContract = None,
        enable_physics: bool = False,
        phrackify: bool = False,
        transaction_count: Optional[int] = None,
    ) -> str:
        """

        :param contract: The Contract on which the analysis should be done
        :param enable_physics: If true then enables the graph physics simulation
        :param phrackify: If true generates Phrack-style call graph
        :param transaction_count: The amount of transactions to be executed
        :return: The generated graph in html format
        """

        sym = SymExecWrapper(
            contract or self.contracts[0],
            self.address,
            self.strategy,
            dynloader=DynLoader(self.eth, active=self.use_onchain_data),
            max_depth=self.max_depth,
            execution_timeout=self.execution_timeout,
            transaction_count=transaction_count,
            create_timeout=self.create_timeout,
            disable_dependency_pruning=self.disable_dependency_pruning,#false
            run_analysis_modules=False,
            custom_modules_directory=self.custom_modules_directory,
        )
        return generate_graph(sym, physics=enable_physics, phrackify=phrackify)

