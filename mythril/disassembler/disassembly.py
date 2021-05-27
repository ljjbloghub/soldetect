"""This module contains the class used to represent disassembly code."""
from mythril.ethereum import util
from mythril.disassembler import asm
from mythril.support.signatures import SignatureDB

from typing import Dict, List, Tuple


class Disassembly(object):
    """Disassembly class.

    存储字节码和对应反汇编指令集
    Additionally it will gather the following information on the existing functions in the disassembled code:
    - function hashes
    - function name to entry point mapping
    - function entry point to function name mapping
    """

    def __init__(self, code: str, enable_online_lookup: bool = False) -> None:
        """

        :param code:
        :param enable_online_lookup:
        """
        self.bytecode = code
        self.instruction_list = asm.disassemble(util.safe_decode(code))#反汇编evm字节码，返回对应指令集字典
        self.func_hashes = []  # type: List[str]
        self.function_name_to_address = {}  # type: Dict[str, int]
        self.address_to_function_name = {}  # type: Dict[int, str]
        self.enable_online_lookup = enable_online_lookup
        self.assign_bytecode(bytecode=code)#添加 调用表项的函数信息 function_name:address
      
    def assign_bytecode(self, bytecode):
        self.bytecode = bytecode
        # open from default locations
        # control if you want to have online signature hash lookups
        signatures = SignatureDB(enable_online_lookup=self.enable_online_lookup)
        self.instruction_list = asm.disassemble(util.safe_decode(bytecode))
        # Need to take from PUSH1 to PUSH4 because solc seems to remove excess 0s at the beginning for optimizing
        jump_table_indices = asm.find_op_code_sequence(
            [("PUSH1", "PUSH2", "PUSH3", "PUSH4"), ("EQ",)], self.instruction_list
        )#返回pushx后为指令eq的指令在instruction_list中的索引,因为可能是函数调用指令的特征

        for index in jump_table_indices:
            function_hash, jump_target, function_name = get_function_info(
                index, self.instruction_list, signatures
            )#判断是否为函数调用，并返回函数信息
            self.func_hashes.append(function_hash)
            if jump_target is not None and function_name is not None:
                self.function_name_to_address[function_name] = jump_target
                self.address_to_function_name[jump_target] = function_name

    def get_easm(self):
        """

        :return:
        """
        return asm.instruction_list_to_easm(self.instruction_list)


def get_function_info(
    index: int, instruction_list: list, signature_database: SignatureDB
) -> Tuple[str, int, str]:
    """ 查找Solidity使用的调用表项的函数信息

    calldata的前4个字节，用于指示消息调用哪个函数

    应执行生成的代码，该代码将执行定向到正确的函数如下所示 :

    - PUSH function_hash
    - EQ
    - PUSH entry_point
    - JUMPI

    {'address': 62, 'opcode': 'PUSH4', 'argument': '0x7536185e'}
    {'address': 67, 'opcode': 'EQ'}
    {'address': 68, 'opcode': 'PUSH1', 'argument': '0x37'}#int(0x37,16)=55
    {'address': 70, 'opcode': 'JUMPI'}
    返回
    {'callchecked(address)': 55}
    :param index: Start of the entry pattern
    :param instruction_list: Instruction list for the contract that is being analyzed
    :param signature_database: Database used to map function hashes to their respective function names
    :return: function hash, function entry point, function name
    """

    # Append with missing 0s at the beginning
    function_hash = "0x" + instruction_list[index]["argument"][2:].rjust(8, "0") 
    function_names = signature_database.get(function_hash)

    if len(function_names) > 0:
        function_name = function_names[0]
    else:
        function_name = "_function_" + function_hash

    try:
        offset = instruction_list[index + 2]["argument"]
        entry_point = int(offset, 16)#将16进制转换为int 即push1 argment值
    except (KeyError, IndexError):
        return function_hash, None, None

    return function_hash, entry_point, function_name
