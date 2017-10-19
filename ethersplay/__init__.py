#from __future__ import print_function

from binaryninja import PluginCommand

from printSourceCode import function_source_code_start

from coverage import function_coverage_start
from evm import EVM, EVMView

PluginCommand.register("EVM Source Code",
                       "EVM Source Code Printer.",
                       function_source_code_start)

PluginCommand.register("EVM Manticore Highlight",
                       "EVM Manticore Highlight",
                       function_coverage_start)


EVM.register()
EVMView.register()
