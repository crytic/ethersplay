from binaryninja import PluginCommand, Architecture

from printSourceCode import function_source_code_start
from coverage import function_coverage_start
from print_stack import function_printStack_start
from evm import EVM, EVMView


def is_valid_evm(view):
    return view.arch == Architecture['EVM']


PluginCommand.register("EVM Source Code",
                       "EVM Source Code Printer.",
                       function_source_code_start,
                       is_valid=is_valid_evm)

PluginCommand.register("EVM Manticore Highlight",
                       "EVM Manticore Highlight",
                       function_coverage_start,
                       is_valid=is_valid_evm)


PluginCommand.register_for_function("EVM Print stack",
                                    "Print up to 10 values of the stack",
                                    function_printStack_start)

EVM.register()
EVMView.register()
