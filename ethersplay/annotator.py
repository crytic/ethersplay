from binaryninja import log_error

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


def get_annotation_for_stack_offset(function, address, offset=0):
    """offset is in terms of EVM stack slots"""

    sp = function.get_reg_value_at(address, 'sp')
    # sp should be a offset
    if hasattr(sp, 'offset'):
        spoff = sp.offset
    else:
        # binary ninja couldn't track the sp offset. bail out early
        return "<??? sp = " + str(sp) + ">"

    val = function.get_stack_contents_at(address, spoff + ADDR_SZ * offset,
                                         ADDR_SZ)
    if hasattr(val, 'value'):
        if val.value > 2**10:
            return hex(val.value)
        else:
            return str(val.value)
    else:
        return "<???>"


_ANNOTATIONS = {
    "CALLDATALOAD": ('input_offset', ),
    "CALLDATACOPY": ('mem_offset', 'input_offset', 'len'),
    'CODECOPY': ('mem_offset', 'code_offset', 'len'),
    'EXTCODECOPY': ('addr', 'mem_offset', 'code_offset', 'len'),
    "MSTORE": ('address', 'value'),
    "SSTORE": ('address', 'value'),
    "SLOAD": ('address', ),
    "MLOAD": ('address', ),
    "CREATE": ('value', 'mem_offset', 'mem_size'),
    "CALL": ('gas', 'address', 'value', 'inp_offset', 'inp_size', 'ret_offset',
             'ret_size'),
    "CALLCODE": ('gas', 'address', 'value', 'inp_offset', 'inp_size',
                 'ret_offset', 'ret_size'),
    "DELEGATECALL": ('gas', 'address', 'inp_offset', 'inp_size', 'ret_offset',
                     'ret_size'),
    "STATICCALL": ('gas', 'address', 'inp_offset', 'inp_size', 'ret_offset',
                   'ret_size'),
    "RETURN": ('mem_offset', 'mem_size'),
    "REVERT": ('mem_offset', 'mem_size'),
    "SUICIDE": ('address', ),
}


def annotate(view, function):
    if view.arch.name != 'evm':
        log_error("This plugin works only for EVM bytecode")
        return -1

    # registers = bv.platform.system_call_convention.int_arg_regs
    # for block in function.low_level_il:
    #     for instruction in block:
    #         if instruction.operation == LowLevelILOperation.LLIL_SYSCALL:
    #             handle_evm_call(instruction, view, function)

    for inst, address in function.instructions:
        inststr = str(inst[0]).strip()
        if inststr in _ANNOTATIONS:
            comment = ""
            for stack_offset, annotation in enumerate(_ANNOTATIONS[inststr]):
                if annotation:
                    comment += (", {} = {}"
                                .format(annotation,
                                        get_annotation_for_stack_offset(
                                            function, address, stack_offset)))
            if comment:
                # skip initial ', '
                comment = comment[2:]
                if len(comment) > 50:  # this number is pretty arbitrary
                    comment = comment.replace(", ", ",\n")
                function.set_comment(address, comment)


def annotate_all(view):
    if view.arch.name != 'evm':
        log_error("This plugin works only for EVM bytecode")
        return -1

    for f in view.functions:
        annotate(view, f)
