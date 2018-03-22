from binaryninja import log_error, LowLevelILOperation

from constants import ADDR_SZ
from evm_llil import TrapInstructions

_numberToName = {v: k for k, v in TrapInstructions.iteritems()}


def handle_evm_call(instruction, view, function):
    possible_value = instruction.get_reg_value("evm_call_nr")
    if (hasattr(possible_value, 'value')):
        calltype = _numberToName[possible_value.value]
    else:
        log_error("couldn't determine syscall number for instruction @ " +
                  str(instruction.address))
        return

    comment = ""
    if calltype in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
        possible_value = instruction.get_reg_value("evm_call_arg1")
        if (hasattr(possible_value, 'value')):
            comment += "target = " + hex(possible_value.value)
        else:
            comment += "target = <unknown>"

    if calltype in ('CALL', 'CALLCODE'):
        comment += "\n"
        possible_value = instruction.get_reg_value("evm_call_arg2")
        if (hasattr(possible_value, 'value')):
            comment += "value = " + str(possible_value.value)
        else:
            comment += "value = <unknown>"

    if comment:
        function.set_comment(instruction.address, comment)


def handle_store(function, instruction, address):
    sp = function.get_reg_value_at(address, 'sp')
    # sp should be a offset
    if hasattr(sp, 'offset'):
        spoff = sp.offset
    else:
        # binary ninja couldn't track the sp offset. bail out early
        function.set_comment(
            address, "address, value = <undetermined> (sp = " + str(sp) + ")")
        return

    mstore_addr = function.get_stack_contents_at(address, spoff, ADDR_SZ)
    mstore_val = function.get_stack_contents_at(address, spoff + ADDR_SZ,
                                                ADDR_SZ)
    comment = "address = "
    if hasattr(mstore_addr, 'value'):
        comment += hex(mstore_addr.value)
    else:
        comment += "<undetermined>"
    comment += ", value = "
    if hasattr(mstore_val, 'value'):
        if mstore_val.value > 2**10:
            comment += hex(mstore_val.value)
        else:
            comment += str(mstore_val.value)
    else:
        comment += "<undetermined>"
    function.set_comment(address, comment)


def handle_load(function, instruction, address):
    sp = function.get_reg_value_at(address, 'sp')
    # sp should be a offset
    if hasattr(sp, 'offset'):
        spoff = sp.offset
    else:
        # binary ninja couldn't track the sp offset. bail out early
        function.set_comment(
            address, "address = <undetermined> (sp = " + str(sp) + ")")
        return
    m_addr = function.get_stack_contents_at(address, spoff, ADDR_SZ)
    comment = "address = "
    if hasattr(m_addr, 'value'):
        comment += hex(m_addr.value)
    else:
        comment += "<undetermined>"
    # comment += ", value = "
    function.set_comment(address, comment)


def annotate(view, function):
    if view.arch.name != 'evm':
        log_error("This plugin works only for EVM bytecode")
        return -1

    # registers = bv.platform.system_call_convention.int_arg_regs

    for block in function.low_level_il:
        for instruction in block:
            if instruction.operation == LowLevelILOperation.LLIL_SYSCALL:
                handle_evm_call(instruction, view, function)

    for inst, address in function.instructions:
        if (str(inst[0]).startswith("MSTORE")
                or str(inst[0]).startswith("SSTORE")):
            handle_store(function, inst, address)
        elif (str(inst[0]).startswith("MLOAD")
              or str(inst[0]).startswith("SLOAD")):
            handle_load(function, inst, address)
