import cPickle
import sys

from binaryninja import (BinaryDataNotification, BranchType,
                         IntegerDisplayType, MediumLevelILOperation,
                         SegmentFlag, SSAVariable, Symbol, SymbolType,
                         log_debug, BackgroundTaskThread, Setting)
from evm_cfg_builder import cfg_builder
from evm_cfg_builder.cfg import Function as EvmFunction
from evm_cfg_builder.cfg import compute_instructions, find_functions
from evm_cfg_builder.evm_helpers import create_dicts_from_basic_blocks
from evm_cfg_builder.value_set_analysis import StackValueAnalysis
from pyevmasm import disassemble_all

from .common import EVM_HEADER
from .evmvisitor import EVMVisitor
from .known_hashes import knownHashes

try:
    import builtins
except ImportError:
    pass

if sys.version_info.major > 2:
    xrange = range

def run_vsa(view, function):
    try:
        basic_blocks_as_dict = cPickle.loads(
            view.query_metadata('ethersplay.basic_blocks'))
        nodes_as_dict = cPickle.loads(
            view.query_metadata('ethersplay.instructions'))
        functions = cPickle.loads(view.query_metadata('ethersplay.functions'))
    except KeyError:
        data = view.read(view.start, len(view))
        instructions = disassemble_all(data)
        basic_blocks = compute_instructions(instructions)
        (basic_blocks_as_dict, nodes_as_dict) = create_dicts_from_basic_blocks(
            basic_blocks)
        functions = find_functions(basic_blocks[0], basic_blocks_as_dict, True)

    for discovered_function in functions:
        if view.get_function_at(discovered_function._start_addr + 1) is None:
            h = hex(discovered_function.hash_id)
            if h in knownHashes:
                discovered_function.name = knownHashes[h]

            view.add_function(discovered_function._start_addr + 1)
            new_function = view.get_function_at(
                discovered_function._start_addr + 1)
            new_function.name = discovered_function.name

    vsa = StackValueAnalysis(
        basic_blocks_as_dict[
            function.start - 1 if function.start != 0 else 0
        ],
        basic_blocks_as_dict,
        nodes_as_dict,
        function.name
    )

    basic_blocks = vsa.analyze()

    to_process = [
        basic_blocks_as_dict
        [
            function.start - 1 if function.start != 0 else 0
        ]
    ]
    seen = set()

    while to_process:
        basic_block = to_process.pop()
        seen.add(basic_block)
        end = basic_block.end.pc
        sons = basic_block.sons.get(function.name)
        if sons is not None:
            for son in sons:
                if (view.get_function_at(son.start.pc + 1) is None and
                        son not in seen):
                    to_process.append(son)

                dest_branches = function.get_indirect_branches_at(end)

                current_branches = {
                    dest.dest_addr for dest in dest_branches
                }

                if son.start.pc not in current_branches:
                    current_branches.add(son.start.pc)
                    function.set_user_indirect_branches(
                        end,
                        [
                            (view.arch, dest) for dest in current_branches
                            if (not basic_block.ends_with_jumpi or
                                son.start.pc != end + 1)
                        ]
                    )

    new_basic_blocks_as_dict = cPickle.dumps(basic_blocks_as_dict)
    new_nodes_as_dict = cPickle.dumps(nodes_as_dict)
    new_functions = cPickle.dumps(functions)

    try:
        if new_basic_blocks_as_dict != view.query_metadata(
                'ethersplay.basic_blocks'):
            view.store_metadata(
                'ethersplay.basic_blocks',
                new_basic_blocks_as_dict
            )
    except KeyError:
        view.store_metadata(
            'ethersplay.basic_blocks',
            new_basic_blocks_as_dict
        )

    try:
        if new_nodes_as_dict != view.query_metadata(
            'ethersplay.instructions'):
            view.store_metadata(
                'ethersplay.instructions', 
                new_nodes_as_dict
                )
    except KeyError:
        view.store_metadata(
            'ethersplay.instructions', 
            new_nodes_as_dict
            )

    try:
        if new_functions != view.query_metadata('ethersplay.functions'):
            view.store_metadata('ethersplay.functions', new_functions)
    except KeyError:
        view.store_metadata('ethersplay.functions', new_functions)

    if function.start == 0:
        analysis_settings = Setting('analysis')
        if analysis_settings.is_present('max-function-size'):
            view.max_function_size_for_analysis = analysis_settings.get_integer('max-function-size')
        else:
            view.max_function_size_for_analysis = 65536


class VsaTaskThread(BackgroundTaskThread):
    def __init__(self, status, view, function):
        BackgroundTaskThread.__init__(self, status, False)
        self.view = view
        self.function = function

    def run(self):
        run_vsa(self.view, self.function)


class VsaNotification(BinaryDataNotification):
    def function_added(self, view, function):
        vsa_task = VsaTaskThread(
            'Running VSA for {}'.format(function.name), view, function)
        vsa_task.start()


def vsa_completion_event(evt):
    view = evt.view
    function = view.get_function_at(view.entry_point)
    vsa_task = VsaTaskThread('Running VSA for _dispatcher', view, function)
    vsa_task.start()
