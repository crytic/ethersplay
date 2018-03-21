from binaryninja import log_error, LowLevelILOperation

from evm_llil import TrapInstructions

_numberToName = {v: k for k, v in TrapInstructions.iteritems()}


def handle_evm_call(instruction, view, function):
    possible_value = instruction.get_reg_value("evm_call_nr")
    if(hasattr(possible_value, 'value')):
        calltype = _numberToName[possible_value.value]
    else:
        log_error("couldn't determine syscall number for instruction @ " +
                  str(instruction.address))
        return

    comment = ""
    if calltype in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
        possible_value = instruction.get_reg_value("evm_call_arg1")
        if(hasattr(possible_value, 'value')):
            comment += "target = " + hex(possible_value.value)
        else:
            comment += "target = <unknown>"

    if calltype in ('CALL', 'CALLCODE'):
        comment += "\n"
        possible_value = instruction.get_reg_value("evm_call_arg2")
        if(hasattr(possible_value, 'value')):
            comment += "value = " + str(possible_value.value)
        else:
            comment += "value = <unknown>"

    if comment:
        function.set_comment(instruction.address, comment)


def analyze_call_targets(view, function):
    if view.arch.name != 'evm':
        log_error("This plugin works only for EVM bytecode")
        return -1

    # registers = bv.platform.system_call_convention.int_arg_regs

    for block in function.low_level_il:
        for instruction in block:
            if instruction.operation == LowLevelILOperation.LLIL_SYSCALL:
                handle_evm_call(instruction, view, function)
