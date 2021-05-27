"""This module contains representation classes for Solidity files, contracts
and source mappings."""
from typing import Dict, Set

import mythril.laser.ethereum.util as helper
from mythril.ethereum.evmcontract import EVMContract
from mythril.ethereum.util import get_solc_json
from mythril.exceptions import NoContractFoundError


class SourceMapping:
    def __init__(self, solidity_file_idx, offset, length, lineno, mapping):
        """Representation of a source mapping for a Solidity file."""

        self.solidity_file_idx = solidity_file_idx
        self.offset = offset
        self.length = length
        self.lineno = lineno
        self.solc_mapping = mapping


class SolidityFile:
    """Representation of a file containing Solidity code."""

    def __init__(self, filename: str, data: str, full_contract_src_maps: Set[str]):
        """
        Metadata class containing data regarding a specific solidity file
        :param filename: The filename of the solidity file
        :param data: The code of the solidity file
        :param full_contract_src_maps: The set of contract source mappings of all the contracts in the file
        """
        self.filename = filename
        self.data = data
        self.full_contract_src_maps = full_contract_src_maps


class SourceCodeInfo:
    def __init__(self, filename, lineno, code, mapping):
        """Metadata class containing a code reference for a specific file."""

        self.filename = filename
        self.lineno = lineno
        self.code = code
        self.solc_mapping = mapping


def get_contracts_from_file(input_file, solc_settings_json=None, solc_binary="solc"):
    """

    :param input_file:
    :param solc_settings_json:
    :param solc_binary:
    """
    #返回反汇编的json结果
    data = get_solc_json(
        input_file, solc_settings_json=solc_settings_json, solc_binary=solc_binary
    )


    try:
        for contract_name in data["contracts"][input_file].keys():#contract contract_name{}
            if len(
                data["contracts"][input_file][contract_name]["evm"]["deployedBytecode"][
                    "object"
                ]
            ):
                yield SolidityContract(
                    input_file=input_file,
                    name=contract_name,
                    solc_settings_json=solc_settings_json,
                    solc_binary=solc_binary,
                )
    except KeyError:
        raise NoContractFoundError


class SolidityContract(EVMContract):
    """Representation of a Solidity contract."""
    #定义描述Solidity contract的信息，如ast中src，offset，字节码等等。保存在solidity_files[],self.mappings[]等。初始化EVMContract对象，包含反汇编指令的disassembly对象。。
    def __init__(
        self, input_file, name=None, solc_settings_json=None, solc_binary="solc"
    ):
        data = get_solc_json(
            input_file, solc_settings_json=solc_settings_json, solc_binary=solc_binary
        )

        self.solidity_files = []
        self.solc_json = data
        self.input_file = input_file

        for filename, contract in data["sources"].items():
            with open(filename, "r", encoding="utf-8") as file:
                code = file.read()
                #返回ast中的src值 {'64:143:0'}
                full_contract_src_maps = self.get_full_contract_src_maps(
                    contract["ast"]
                )
                #添加SolidityFile对象，存在filename，源码和ast中的src值('src': '38:23:0')
                self.solidity_files.append(
                    SolidityFile(filename, code, full_contract_src_maps)
                )

        has_contract = False

        # If a contract name has been specified, find the bytecode of that specific contract
        srcmap_constructor = []
        srcmap = []
        if name:
            contract = data["contracts"][input_file][name]
            if len(contract["evm"]["deployedBytecode"]["object"]):
                code = contract["evm"]["deployedBytecode"]["object"]#字节码6080604...
                creation_code = contract["evm"]["bytecode"]["object"]
                srcmap = contract["evm"]["deployedBytecode"]["sourceMap"].split(";") #' 'sourceMap': '64:143:0:-:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;90:54;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::i;:::-;;148:57;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::i;:::-;;90:54;;:::o;148:57::-;;:::o'
                srcmap_constructor = contract["evm"]["bytecode"]["sourceMap"].split(";")#'sourceMap': '64:143:0:-:0;;;;;;;;;;;;;;;;;;;'  offset:length:idx
                has_contract = True

        # If no contract name is specified, get the last bytecode entry for the input file

        else:
            for contract_name, contract in sorted(
                data["contracts"][input_file].items()
            ):
                if len(contract["evm"]["deployedBytecode"]["object"]):
                    name = contract_name
                    code = contract["evm"]["deployedBytecode"]["object"]
                    creation_code = contract["evm"]["bytecode"]["object"]
                    srcmap = contract["evm"]["deployedBytecode"]["sourceMap"].split(";")
                    srcmap_constructor = contract["evm"]["bytecode"]["sourceMap"].split(
                        ";"
                    )
                    has_contract = True

        if not has_contract:
            raise NoContractFoundError

        self.mappings = []

        self.constructor_mappings = []
        self._get_solc_mappings(srcmap)#根据ast文件生成SourceMapping对象的列表self.mappings = []
        self._get_solc_mappings(srcmap_constructor, constructor=True)

        super().__init__(code, creation_code, name=name)#定义bytecode和deployedBytecode，contractname并对bytecode进行反汇编获取指令集！！

    @staticmethod
    def get_full_contract_src_maps(ast: Dict) -> Set[str]:
        """
        返回ast中的src值'src': '64:143:0'
        Takes a solc AST and gets the src mappings for all the contracts defined in the top level of the ast
        :param ast: AST of the contract
        :return: The source maps
        """
        source_maps = set()
        for child in ast["nodes"]:
            if child.get("contractKind"):
                source_maps.add(child["src"])
        
        return source_maps

    def get_source_info(self, address, constructor=False):
        """

        :param address:
        :param constructor:
        :return:
        """
        disassembly = self.creation_disassembly if constructor else self.disassembly
        mappings = self.constructor_mappings if constructor else self.mappings
        index = helper.get_instruction_index(disassembly.instruction_list, address)

        solidity_file = self.solidity_files[mappings[index].solidity_file_idx]
        filename = solidity_file.filename

        offset = mappings[index].offset
        length = mappings[index].length

        code = solidity_file.data.encode("utf-8")[offset : offset + length].decode(
            "utf-8", errors="ignore"
        )
        lineno = mappings[index].lineno
        return SourceCodeInfo(filename, lineno, code, mappings[index].solc_mapping)

    def _is_autogenerated_code(self, offset: int, length: int, file_index: int) -> bool:
        """
        Checks whether the code is autogenerated or not
        :param offset: offset of the code
        :param length: length of the code
        :param file_index: file the code corresponds to
        :return: True if the code is internally generated, else false
        """

        """Handle internal compiler files
        The second condition will be placed till 
        https://github.com/ethereum/solidity/issues/10300 is dealt
        """
        if file_index == -1 or file_index >= len(self.solidity_files):
            return True
        # Handle the common code src map for the entire code.
        if (
            "{}:{}:{}".format(offset, length, file_index)
            in self.solidity_files[file_index].full_contract_src_maps
        ):
            return True

        return False

    def _get_solc_mappings(self, srcmap, constructor=False):
        """
        #根据ast文件生成SourceMapping对象的列表，包含dx, offset, length, lineno, item属性
        :param srcmap:
        :param constructor:
        """
        mappings = self.constructor_mappings if constructor else self.mappings #[]

        prev_item = ""
        for item in srcmap:#['64:143:0:-:0,'','148:57::-', '', ':::o']
            if item == "":
                item = prev_item
            mapping = item.split(":")#['64', '143', '0', '-', '0']

            if len(mapping) > 0 and len(mapping[0]) > 0:
                offset = int(mapping[0])

            if len(mapping) > 1 and len(mapping[1]) > 0:
                length = int(mapping[1])

            if len(mapping) > 2 and len(mapping[2]) > 0:
                idx = int(mapping[2])

            if self._is_autogenerated_code(offset, length, idx):#判断是否是自动生成的code
                lineno = None
            else:
                lineno = (
                    self.solidity_files[idx]
                    .data.encode("utf-8")[0:offset]
                    .count("\n".encode("utf-8"))
                    + 1
                )

            prev_item = item
            #添加SourceMapping对象，idx, offset, length, lineno, item属性
            mappings.append(SourceMapping(idx, offset, length, lineno, item))

