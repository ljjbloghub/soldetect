"""This module contains various helper classes and functions to deal with EVM
code disassembly."""

import re
from collections import Generator

from mythril.support.opcodes import opcodes

regex_PUSH = re.compile(r"^PUSH(\d*)$")

# Additional mnemonic to catch failed assertions
opcodes[254] = ("ASSERT_FAIL", 0, 0, 0)


class EvmInstruction:
    """Model to hold the information of the disassembly."""

    def __init__(self, address, op_code, argument=None):
        self.address = address
        self.op_code = op_code
        self.argument = argument

    def to_dict(self) -> dict:
        """

        :return:
        """
        result = {"address": self.address, "opcode": self.op_code}
        if self.argument:
            result["argument"] = self.argument
        return result


def instruction_list_to_easm(instruction_list: list) -> str:
    """Convert a list of instructions into an easm op code string.
    格式化instruction_list
    :param instruction_list:
    :return:
    """
    result = ""
   

    for instruction in instruction_list:
        result += "{} {}".format(instruction["address"], instruction["opcode"])
        if "argument" in instruction:
            result += " " + instruction["argument"]
        result += "\n"
    
    return result


def get_opcode_from_name(operation_name: str) -> int:
    """Get an op code based on its name.

    :param operation_name:
    :return:
    """
    for op_code, value in opcodes.items():
        if operation_name == value[0]:
            return op_code
    raise RuntimeError("Unknown opcode")


def find_op_code_sequence(pattern: list, instruction_list: list) -> Generator:
    """返回instruction_list中所有["PUSH1", "PUSH2"。。]指令后是"EQ"]指令的索引index 
           index 23 {'address': 31, 'opcode': 'PUSH4', 'argument': '0x7536185e'}
           index 23 {'address': 36, 'opcode': 'EQ'}
        return 23

    :param pattern: The pattern to look for, e.g. [["PUSH1", "PUSH2"], ["EQ"]] where ["PUSH1", "EQ"] satisfies pattern
    :param instruction_list: List of instructions to look in
    :return: Indices to the instruction sequences
    """
    for i in range(0, len(instruction_list) - len(pattern) + 1):
        if is_sequence_match(pattern, instruction_list, i):
            yield i


def is_sequence_match(pattern: list, instruction_list: list, index: int) -> bool:
    """Checks if the instructions starting at index follow a pattern.

    :param pattern: List of lists describing a pattern, e.g. [["PUSH1", "PUSH2"], ["EQ"]] where ["PUSH1", "EQ"] satisfies pattern
    :param instruction_list: List of instructions
    :param index: Index to check for
    :return: Pattern matched
    """
    for index, pattern_slot in enumerate(pattern, start=index):

        try:
            if not instruction_list[index]["opcode"] in pattern_slot:
                return False
        except IndexError:
            return False
    return True


def disassemble(bytecode: bytes) -> list:
    """
    反汇编evm字节码，返回对应指令集字典{'address': 8, 'opcode': 'PUSH1', 'argument': '0x0f'}
    Disassembles evm bytecode and returns a list of instructions.
    import opcodes opcodes={0: ('STOP', 0, 0, 0), 1: ('ADD', 2, 1, 3), 2: ('MUL', 2, 1, 5)..} #add ->0x01
    :param bytecode:
    :return:
    """
    instruction_list = []
    address = 0
    length = len(bytecode)

    if "bzzr" in str(bytecode[-43:]):
        # 编译器可能会将元数据的Swarm哈希附加到每个合约的字节码末尾，以bzzr开头
        length -= 43


    while address < length:
        try:
            #bytecode[address]返回字节码对应的十进制数
            op_code = opcodes[bytecode[address]]
            
        except KeyError:
            instruction_list.append(EvmInstruction(address, "INVALID"))
            address += 1
            continue

        op_code_name = op_code[0]
        current_instruction = EvmInstruction(address, op_code_name) #EvmInstruction对象类型，属性为address，opcodename，可以返回字典数据

        match = re.search(regex_PUSH, op_code_name)#如果指令为pushx(存放x个字节的数值到栈中),match.group(1)=x
        if match:
            argument_bytes = bytecode[address + 1 : address + 1 + int(match.group(1))]#返回x字节对应字节值
            current_instruction.argument = "0x" + argument_bytes.hex()
            address += int(match.group(1))

        instruction_list.append(current_instruction)
        address += 1

    # 返回由指令集字典{"address": self.address, "opcode": self.op_code}组成的列表
    return [element.to_dict() for element in instruction_list]
