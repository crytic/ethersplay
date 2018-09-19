from binaryninja import PluginCommand, Architecture

from printSourceCode import function_source_code_start
from coverage import function_coverage_start
from print_stack import function_printStack_start
from stack_value_analysis import stack_value_analysis_plugin
from analysis import analyze_jumps
from evm import EVM, EVMView


def is_valid_evm(view, function=None):
    return view.arch == Architecture['EVM']


PluginCommand.register("EVM Source Code",
                       "EVM Source Code Printer.",
                       function_source_code_start,
                       is_valid=is_valid_evm)

PluginCommand.register("EVM Manticore Highlight",
                       "EVM Manticore Highlight",
                       function_coverage_start,
                       is_valid=is_valid_evm)

PluginCommand.register_for_function("EVM Stack Value Analysis",
                                    "Run value-set analysis on the function",
                                    stack_value_analysis_plugin,
                                    is_valid=is_valid_evm)

PluginCommand.register_for_function("EVM Print stack",
                                    "Print up to 10 values of the stack",
                                    function_printStack_start,
                                    is_valid=is_valid_evm)

PluginCommand.register_for_function('EVM Identify Dispatches',
                                    'Locate dispatch functions and label them',
                                    analyze_jumps,
                                    is_valid=is_valid_evm)


EVM.register()
EVMView.register()
