import sys
import threading

from pyevmasm import disassemble_all

from binaryninja import (BackgroundTaskThread, BinaryDataNotification,
                         BranchType, IntegerDisplayType,
                         MediumLevelILOperation, SegmentFlag, Settings,
                         SettingsScope, SSAVariable, Symbol, SymbolType,
                         log_debug, log_info)
from evm_cfg_builder.cfg import CFG
from evm_cfg_builder.known_hashes import known_hashes
from evm_cfg_builder.value_set_analysis import StackValueAnalysis

from .evmvisitor import EVMVisitor


def run_vsa(thread, view, function):
    cfg = function.session_data.cfg
    cfg_function = cfg.get_function_at(
        function.start - 1 if function.start != 0 else 0
    )
    hash_id = cfg_function.hash_id

    thread.task.progress = '[VSA] Analyzing...'

    to_process = [
        cfg.get_basic_block_at
        (
            function.start - 1 if function.start != 0 else 0
        )
    ]

    seen = set()

    i = 3

    while to_process:
        thread.task.progress = '[VSA] Processing Basic Blocks{}'.format('.'*i)
        i += (i + 1) % 4
        basic_block = to_process.pop()
        seen.add(basic_block)
        end = basic_block.end.pc
        outgoing_edges = basic_block.outgoing_basic_blocks(hash_id)

        if outgoing_edges is not None:
            for outgoing_edge in outgoing_edges:
                if (view.get_function_at(outgoing_edge.start.pc + 1) is None and
                        outgoing_edge not in seen):
                    to_process.append(outgoing_edge)

                dest_branches = function.get_indirect_branches_at(end)

                current_branches = {
                    dest.dest_addr for dest in dest_branches
                }

                if outgoing_edge.start.pc not in current_branches:
                    current_branches.add(outgoing_edge.start.pc)
                    function.set_user_indirect_branches(
                        end,
                        [
                            (view.arch, dest) for dest in current_branches
                            if (not basic_block.ends_with_jumpi or
                                outgoing_edge.start.pc != end + 1)
                        ]
                    )

    if function.start == 0:
        max_function_size, _ = Settings().get_integer_with_scope(
            'analysis.maxFunctionSize', scope=SettingsScope.SettingsDefaultScope)
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
