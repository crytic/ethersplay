from binaryninja import PluginCommand

from evm import EVM, EVMView

from printSourceCode import function_source_code_start
from coverage import function_coverage_start
from call_targets import analyze_call_targets

PluginCommand.register("EVM Source Code", "EVM Source Code Printer.",
                       function_source_code_start)

PluginCommand.register("EVM Manticore Highlight", "EVM Manticore Highlight",
                       function_coverage_start)

PluginCommand.register_for_function("EVM Analyze CALL Targets (via LLIL)",
                                    "EVM Analyze CALL Targets (via LLIL)",
                                    analyze_call_targets)

EVM.register()
EVMView.register()
