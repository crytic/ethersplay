from binaryninja import PluginCommand, Architecture

from .printSourceCode import function_source_code_start
from .coverage import function_coverage_start
from .print_stack import function_printStack_start
from .evm import EVM, EVMView
from .flowgraph import render_flowgraphs


def is_valid_evm(view, function=None):
    return view.arch == Architecture['EVM']


PluginCommand.register(
    r"Ethersplay\Manticore Highlight",
    "EVM Manticore Highlight",
    function_coverage_start,
    is_valid=is_valid_evm
)

PluginCommand.register(
    r'Ethersplay\Render Flowgraphs',
    'Render flowgraphs of every function, removing stack variable annotations',
    render_flowgraphs,
    is_valid=is_valid_evm
)

EVM.register()
EVMView.register()
