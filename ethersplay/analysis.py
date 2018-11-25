try:
    import cPickle
except ImportError:
    import pickle as cPickle

import sys

from binaryninja import (BackgroundTaskThread, BinaryDataNotification,
                         BranchType, IntegerDisplayType,
                         MediumLevelILOperation, SegmentFlag, Settings, SettingsScope,
                         SSAVariable, Symbol, SymbolType, log_debug, log_info)
from evm_cfg_builder.cfg import CFG
from evm_cfg_builder.known_hashes import known_hashes
from evm_cfg_builder.value_set_analysis import StackValueAnalysis
from pyevmasm import disassemble_all

from .evmvisitor import EVMVisitor


def run_vsa(thread, view, function):
    try:
        basic_blocks = cPickle.loads(
            view.query_metadata('ethersplay.basic_blocks'))
        instructions = cPickle.loads(
            view.query_metadata('ethersplay.instructions')
        )
        functions = cPickle.loads(view.query_metadata('ethersplay.functions'))

        data = view.read(view.start, len(view))
        cfg = CFG(data, instructions, basic_blocks, functions)
    except KeyError:
        data = view.read(view.start, len(view))
        cfg = CFG(data)
        cfg.compute_basic_blocks()
        cfg.compute_functions(cfg.basic_blocks[0], True)

    thread.task.progress = '[VSA] Found Functions'

    for discovered_function in cfg.functions:
        if view.get_function_at(discovered_function._start_addr + 1) is None:
            if discovered_function.hash_id == -1:
                discovered_function.name = '_fallback'
            else:
                if discovered_function.hash_id in known_hashes:
                    discovered_function.name = known_hashes[
                        discovered_function.hash_id
                    ]

            view.add_function(discovered_function._start_addr + 1)
            new_function = view.get_function_at(
                discovered_function._start_addr + 1)
            new_function.name = discovered_function.name
            thread.task.progress = '[VSA] Created Function {}'.format(new_function.name)

    vsa = StackValueAnalysis(
        cfg,
        cfg.basic_blocks[
            (function.start - 1) if function.start != 0 else 0
        ],
        function.name
    )

    thread.task.progress = '[VSA] Analyzing...'

    basic_blocks = vsa.analyze()

    to_process = [
        cfg.basic_blocks
        [
            function.start - 1 if function.start != 0 else 0
        ]
    ]
    seen = set()

    i = 3

    while to_process:
        thread.task.progress = '[VSA] Processing Basic Blocks{}'.format('.'*i)
        i += (i + 1) % 4
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

    new_basic_blocks = cPickle.dumps(cfg.basic_blocks, protocol=2)
    if isinstance(new_basic_blocks, bytes):
        new_basic_blocks = new_basic_blocks.decode('charmap')

    new_instructions = cPickle.dumps(cfg.instructions, protocol=2)
    if isinstance(new_instructions, bytes):
        new_instructions = new_instructions.decode('charmap')
    
    new_functions = cPickle.dumps(cfg.functions, protocol=2)
    if isinstance(new_functions, bytes):
        new_functions = new_functions.decode('charmap')

    try:
        if new_basic_blocks != view.query_metadata(
                'ethersplay.basic_blocks'):
            view.store_metadata(
                'ethersplay.basic_blocks',
                new_basic_blocks
            )
    except KeyError:
        view.store_metadata(
            'ethersplay.basic_blocks',
            new_basic_blocks
        )

    try:
        if new_instructions != view.query_metadata(
            'ethersplay.instructions'):
            view.store_metadata(
                'ethersplay.instructions', 
                new_instructions
                )
    except KeyError:
        view.store_metadata(
            'ethersplay.instructions', 
            new_instructions
            )

    try:
        if new_functions != view.query_metadata('ethersplay.functions'):
            view.store_metadata('ethersplay.functions', new_functions)
    except KeyError:
        view.store_metadata('ethersplay.functions', new_functions)

    if function.start == 0:
        max_function_size, _ = Settings().get_integer_with_scope('analysis.maxFunctionSize', scope=SettingsScope.SettingsDefaultScope)
        if max_function_size:
            view.max_function_size_for_analysis = max_function_size
        else:
            view.max_function_size_for_analysis = 65536


class VsaTaskThread(BackgroundTaskThread):
    def __init__(self, status, view, function):
        BackgroundTaskThread.__init__(self, status, False)
        self.view = view
        self.function = function

    def run(self):
        run_vsa(self.thread, self.view, self.function)


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
