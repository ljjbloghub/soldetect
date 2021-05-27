#!/usr/bin/env python3


import argparse
import json
import os
import sys
import time 
import traceback
import logging


from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from mythril import mythx
from mythril.exceptions import (
    AddressNotFoundError,
    DetectorNotFoundError,
    CriticalError,
)
from mythril.plugin.loader import MythrilPluginLoader
from mythril.mythril import (
    MythrilAnalyzer,
    MythrilDisassembler,
    MythrilConfig,
    MythrilLevelDB,
)

from mythril.analysis.module import ModuleLoader

from mythril.__version__ import __version__ as VERSION

# Initialise core Mythril Component
_ = MythrilPluginLoader() #初始化插件加载，正常无插件加载

log = logging.getLogger(__name__)#
#参数设置
ANALYZE_LIST = ("analyze", "a") #分析模块
DISASSEMBLE_LIST = ("disassemble", "d")#编译模块


COMMAND_LIST = (
    ANALYZE_LIST
    + DISASSEMBLE_LIST
)


def exit_with_error(format_, message):#报错格式化输出
    """
    Exits with error
    :param format_: The format of the message
    :param message: message
    """
    if format_ == "text" or format_ == "markdown":
        log.error(message)
    elif format_ == "json":
        result = {"success": False, "error": str(message), "issues": []}
        print(json.dumps(result))
    else:
        result = [
            {
                "issues": [],
                "sourceType": "",
                "sourceFormat": "",
                "sourceList": [],
                "meta": {"logs": [{"level": "error", "hidden": True, "msg": message}]},
            }
        ]
        print(json.dumps(result))
    sys.exit()


def get_runtime_input_parser() -> ArgumentParser:#接受输入参数，初始化
    """
    Returns Parser which handles input
    :return: Parser which handles input
    """
    parser = ArgumentParser(add_help=False)
    parser.add_argument(
        "-a",
        "--address",
        help="pull contract from the blockchain",
        metavar="CONTRACT_ADDRESS",
    )
    parser.add_argument(
    "--bin-runtime",
    action="store_true",
    help="Only when -c or -f is used. Consider the input bytecode as binary runtime code, default being the contract creation bytecode.",
)

    return parser


def get_creation_input_parser() -> ArgumentParser:
    """
    Returns Parser which handles input
    :return: Parser which handles input
    """
    parser = ArgumentParser(add_help=False)
    parser.add_argument(
        "-c",
        "--code",
        help='hex-encoded bytecode string ("6060604052...")',
        metavar="BYTECODE",
    )
    parser.add_argument(
        "-f",
        "--codefile",
        help="file containing hex-encoded bytecode string",
        metavar="BYTECODEFILE",
        type=argparse.FileType("r"),
    )
    return parser


def get_output_parser() -> ArgumentParser:
    """
    Get parser which handles output
    :return: Parser which handles output
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-o",
        "--outform",
        choices=["text", "markdown", "json", "jsonv2"],
        default="text",
    )
    return parser


def get_rpc_parser() -> ArgumentParser:#获取rpc地址
    """
    Get parser which handles RPC flags
    :return: Parser which handles rpc inputs
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--rpc",
        help="custom RPC settings",
        metavar="HOST:PORT / ganache / infura-[network_name]",
        default="infura-mainnet",
    )
    return parser


def get_utilities_parser() -> ArgumentParser:
    """
    Get parser which handles utilities flags
    :return: Parser which handles utility flags
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--solv",
        help="specify solidity compiler version. If not present, will try to install it (Experimental)",
        metavar="SOLV",
    )
    return parser






def create_disassemble_parser(parser: ArgumentParser):
    """
    Modify parser to handle disassembly
    :param parser:
    :return:
    """
    # Using nargs=* would the implementation below for getting code for both disassemble and analyze
    parser.add_argument(
        "solidity_files",#参数名为solidity_files
        nargs="*",
        help="Inputs file name and contract name. Currently supports a single contract\n"
        "usage: file1.sol:OptionalContractName",
    )


def create_analyzer_parser(analyzer_parser: ArgumentParser):
    """
    Modify parser to handle analyze command
    :param analyzer_parser:
    :return:
    """
    analyzer_parser.add_argument(
        "solidity_files",
        nargs="*",
    )
    commands = analyzer_parser.add_argument_group("commands")
    commands.add_argument("-g", "--graph")#生成控制流程图

    
    options = analyzer_parser.add_argument_group("options")

    options.add_argument(
        "--strategy",
        choices=["dfs", "bfs", "naive-random", "weighted-random"],
        default="bfs",
    )


    options.add_argument(
        "--disable-dependency-pruning",
        action="store_true",
        help="Deactivate dependency-based pruning",
    )
  


def validate_args(args: Namespace):
    """
    验证参数：
        -v 确定日志输出等级；
        disassemble 判断编译模块指定文件是否符合规范
        analyze  mythril.support.signatures中判断是可以import ethereum_input_decoder
    
    """
    if args.command in DISASSEMBLE_LIST and len(args.solidity_files) > 1:#编译模块文件数量大于1报错
        exit_with_error("text", "Only a single arg is supported for using disassemble")



def set_config(args: Namespace):
    """
    设置配置信息：
       infura_id:infura提供了托管的以太坊节点,查看本地环境是否设置infura
       根据命令参数，判断是否从配置文件中导入rpc信息，进行连接
       根据命令参数，判断是否从配置文件中导入leveldb目录，
       最终返回config 类型为MythrilConfig，用于后续操作。
    """
    config = MythrilConfig()#会初始化infura_id，mythril_dir，config_path，leveldb_dir，eth。。

    if args.__dict__.get("rpc", None):
        # Establish RPC connection if necessary
        config.set_api_rpc(rpc=args.rpc)
    
    return config



def load_code(disassembler: MythrilDisassembler, args: Namespace):
    """
    加载代码到反汇编模块,返回address:0x0000000000000000000000000000000000000000
    :param disassembler:
    :param args:
    :return: Address
    """

    address = None
    if args.__dict__.get("code", False):
        # Load from bytecode
        code = args.code[2:] if args.code.startswith("0x") else args.code
        address, _ = disassembler.load_from_bytecode(code, args.bin_runtime)
    elif args.__dict__.get("codefile", False):
        bytecode = "".join([l.strip() for l in args.codefile if len(l.strip()) > 0])
        bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode
        address, _ = disassembler.load_from_bytecode(bytecode, args.bin_runtime)
    elif args.__dict__.get("address", False):
        # Get bytecode from a contract address
        address, _ = disassembler.load_from_address(args.address)
    elif args.__dict__.get("solidity_files", False):
        # Compile Solidity source file(s)
        if args.command in ANALYZE_LIST and args.graph and len(args.solidity_files) > 1:
            exit_with_error(
                args.outform,
                "Cannot generate call graphs from multiple input files. Please do it one at a time.",
            )
        #返回初始地址address；返回SolidityContract类型对象
        address, _ = disassembler.load_from_solidity(
            args.solidity_files
        )  # [solidity_file_name,.]
    else:
        exit_with_error(
            args.__dict__.get("outform", "text"),
            "No input bytecode. Please provide EVM code via -c BYTECODE, -a ADDRESS, -f BYTECODE_FILE or <SOLIDITY_FILE>",
        )
    return address

def main() -> None:
    """The main CLI interface entry point."""
    start=time.time()
    #输入参数初始化
    rpc_parser = get_rpc_parser()
    utilities_parser = get_utilities_parser()
    runtime_input_parser = get_runtime_input_parser()
    creation_input_parser = get_creation_input_parser()
    output_parser = get_output_parser()
    parser = argparse.ArgumentParser(
        description="Security analysis of Ethereum smart contracts"
    )
    parser.add_argument(
        "-v", type=int, help="log level (0-5)", metavar="LOG_LEVEL", default=2
    )
    #subparsers创建子命令
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    #添加子命令analyze
    analyzer_parser = subparsers.add_parser(
        ANALYZE_LIST[0],
        parents=[#继承其他参数设置
            rpc_parser,
            utilities_parser,
            creation_input_parser,
            runtime_input_parser,
            output_parser,
        ],
        aliases=ANALYZE_LIST[1:],
        formatter_class=RawTextHelpFormatter,
    )

    create_analyzer_parser(analyzer_parser)#创建analyze命令解析器

    #添加子命令disassemble
    disassemble_parser = subparsers.add_parser(
        DISASSEMBLE_LIST[0],
        aliases=DISASSEMBLE_LIST[1:],
        parents=[
            rpc_parser,
            utilities_parser,
            creation_input_parser,
            runtime_input_parser,
        ],
        formatter_class=RawTextHelpFormatter,
    )
    create_disassemble_parser(disassemble_parser)


    args = parser.parse_args()#获取命令所有参数
    analyzeresult=parse_args_and_execute(parser=parser, args=args)#获取参数值并执行
    end=time.time()
    analyzetime=end-start

    # print(analyzeresult)
    print(analyzeresult) 

    # print('Running time: %s Seconds'%(end-start))


def parse_args_and_execute(parser: ArgumentParser, args: Namespace) -> None:#获取输入参数值，并执行模块
 

    #解析命令行的参数
    validate_args(args)
    try:
        config = set_config(args)
        solv = args.__dict__.get("solv", None)

        disassembler = MythrilDisassembler(
            eth=config.eth,
            solc_version=solv,
        )

        address = load_code(disassembler, args)
        result=execute_command(
            disassembler=disassembler, address=address, parser=parser, args=args
        )
        return result
    except CriticalError as ce:
        exit_with_error(args.__dict__.get("outform", "text"), str(ce))
    except Exception:
        exit_with_error(args.__dict__.get("outform", "text"), traceback.format_exc())



def execute_command(
    disassembler: MythrilDisassembler,
    address: str,
    parser: ArgumentParser,
    args: Namespace,
):


    if args.command in DISASSEMBLE_LIST:#执行反汇编模块

        if disassembler.contracts[0].code:
            print("Runtime Disassembly: \n" + disassembler.contracts[0].get_easm())#将合约bytecode反汇编结果instruction_list格式化输出
        if disassembler.contracts[0].creation_code:
            print("Disassembly: \n" + disassembler.contracts[0].get_creation_easm())#depoycytecode反汇编输出

    elif args.command in ANALYZE_LIST:
        #漏洞检测模块
        analyzer = MythrilAnalyzer(
            strategy=args.strategy,#选择符号执行策略 "dfs", "bfs", "naive-random", "weighted-random"默认为bfs，广度优先
            disassembler=disassembler,
            address=address,
            max_depth=128,
            execution_timeout=86400,
            loop_bound=3,#默认为 3 的循环边界
            create_timeout=10
        )

        if not disassembler.contracts:
            exit_with_error(
                args.outform, "input files do not contain any valid contracts"
            )

        if args.graph:#生成控制流程图 -g name 
            html = analyzer.graph_html(
                contract=analyzer.contracts[0],
                enable_physics=args.enable_physics,
                phrackify=args.phrack,
                transaction_count=args.transaction_count,#2
            )

            try:
                with open(args.graph, "w") as f:
                    f.write(html)
            except Exception as e:
                exit_with_error(args.outform, "Error saving graph: " + str(e))

        else:
            try:
                report = analyzer.fire_lasers(
                    transaction_count=2
                )#报告生成模块

                outputs = {
                    "json": report.as_json(),
                    "text": report.as_text(),#默认为text
                }
                return outputs[args.outform]
            except DetectorNotFoundError as e:
                exit_with_error(args.outform, format(e))
            except CriticalError as e:
                exit_with_error(
                    args.outform, "Analysis error encountered: " + format(e)
                )

    else:
        parser.print_help()




if __name__ == "__main__":
    
    main()
 
