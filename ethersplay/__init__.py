from binaryninja import PluginCommand

from evm import EVM, EVMView

from printSourceCode import function_source_code_start
from coverage import function_coverage_start
import annotator

PluginCommand.register("EVM Source Code", "EVM Source Code Printer.",
                       function_source_code_start)

PluginCommand.register("EVM Manticore Highlight", "EVM Manticore Highlight",
                       function_coverage_start)

PluginCommand.register("EVM Annotate Instructions",
                       "EVM Annotate Instructions", annotator.annotate_all)

EVM.register()
EVMView.register()
