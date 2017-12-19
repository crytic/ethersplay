import shutil
from manticore.seth import ManticoreEVM
from binaryninja import log
from binaryninja.interaction import get_open_filename_input

from create_methods import CreateMethods
from print_known_hashes import HashMatcher
from stack_value_analysis import function_dynamic_jump_start

import utils

def get_jump(m, state, last_pc, current_instruction, instruction):
    with m.locked_context() as context:
        if instruction.opcode == 0x56:
            context['jump'] += [(last_pc, state.solve_n(current_instruction, 5))]
        if instruction.opcode == 0x57:
            context['jumpi'] += [((last_pc, state.solve_n(current_instruction, 5)))]

class Explore(object):

    def __init__(self, filename, view):
        self.filename = filename
        self.view = view

    def run(self):
        m = ManticoreEVM()
        try:
            with open(self.filename) as f:
                bytecode = f.read()
                m.context['jumpi'] = []
                m.context['jump'] = []
                m.subscribe('did_execute_instruction', get_jump)
                user_account = m.create_account(balance=1000)

                contract_account = m.create_account(address=None, 
                                                          balance=0, 
                                                          code=bytecode)

                m.transaction(caller=user_account,
                                  address=contract_account,
                                  value=None,
                                  data=m.make_symbolic_buffer(320) 
                              )
        except Exception as e:
            log.log(1, e)
        utils.update_branches(self.view, m.context['jump'])
        utils.update_branches(self.view, m.context['jumpi'])
        m.terminate()
        shutil.rmtree(m.workspace)

def function_symbex(view):
    filename = view.file.filename
    explore = Explore(filename, view)
    explore.run()

