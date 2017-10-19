#" TODO to be merged with print_source_code
import os
import sys
from binaryninja.interaction import get_open_filename_input, get_choice_input
from binaryninja import log

path_to_line_number = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   os.sep.join(["..", "utils"]))
sys.path.append(path_to_line_number)

from solidityLineNumber import SolidityLineNumber

class PrintSourceCode(object):

    def __init__(self, solidity_ln, contract_name, view):
        self.bb_seen = []
        self.solidity_ln = solidity_ln
        self.contract_name = contract_name
        self.view = view
        for func in view.functions[1:]: # dont show code on the dispatcher
            self.current_func = func
            self._explore(func.basic_blocks[0])


    def _explore_ins(self, bb):
        addr = bb.start
        prev_txt = ''
        for ins in bb.__iter__():
            ln_desc = self.solidity_ln.get_line(self.contract_name, addr)
            if ln_desc:
                (filename, l_start, l_end, code) = ln_desc
                txt = "{}, lines {}-{}: \"{}\"".format(filename, l_start, l_end, code)
                if prev_txt != txt:
                    prev_txt = txt
                    self.current_func.set_comment(addr, txt)
            else:
                print "Not found " +hex(addr)
            (_, size) = ins
            addr += size

    def _explore(self, bb):
        addr = bb.start
        # the same bb can belong to multiple function
        # so we store the addr alongside the function
        if (addr, self.current_func) in self.bb_seen:
            return
        self.bb_seen.append((addr, self.current_func))

        self._explore_ins(bb)

        for son in bb.outgoing_edges:
            son = son.target
            self._explore(son)

def function_source_code_start(view):
    if view.arch.name != 'evm':
        print "This plugin works only for EVM bytecode"
        return
    filename_asm_json = get_open_filename_input('Asm-json file', "*.asm.json")
    workspace = os.path.dirname(filename_asm_json)

    solidity_ln = SolidityLineNumber(filename_asm_json, workspace=workspace)

    contracts = solidity_ln.contracts.keys()
    contract_index = get_choice_input('Name of the contract', 'Name of the contract', contracts)
    contract_name = contracts[contract_index]

    PrintSourceCode(solidity_ln, contract_name, view)

