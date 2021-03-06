from collections import defaultdict
from typing import List, Optional, Callable, Mapping, Dict
import logging

from mythril.support.opcodes import opcodes
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.module.loader import ModuleLoader

log = logging.getLogger(__name__)
OP_CODE_LIST = [c[0] for _, c in opcodes.items()]


def get_detection_module_hooks(
    modules: List[DetectionModule], hook_type="pre"
) -> Dict[str, List[Callable]]:
    """ 获取带有传递的检测模块的hook的字典
    """
    hook_dict = defaultdict(list)  # type: Mapping[str, List[Callable]]
    for module in modules:

        hooks = module.pre_hooks if hook_type == "pre" else module.post_hooks

        for op_code in map(lambda x: x.upper(), hooks):
            # A hook can be either OP_CODE or START*
            # When an entry like the second is encountered we hook all opcodes that start with START
            if op_code in OP_CODE_LIST:
                hook_dict[op_code].append(module.execute)

            elif op_code.endswith("*"):
                to_register = filter(lambda x: x.startswith(op_code[:-1]), OP_CODE_LIST)
                for actual_hook in to_register:
                    hook_dict[actual_hook].append(module.execute)
            else:
                log.error(
                    "Encountered invalid hook opcode %s in module %s",
                    op_code,
                    module.name,
                )

    return dict(hook_dict)


def reset_callback_modules():
    """Clean the issue records of every callback-based module."""
    modules = ModuleLoader().get_detection_modules(EntryPoint.CALLBACK)
    for module in modules:
        module.reset_module()
