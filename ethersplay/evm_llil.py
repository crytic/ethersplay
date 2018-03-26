from binaryninja import (Architecture, LowLevelILLabel, LLIL_TEMP)

from constants import (ADDR_SZ, MEMORY_PTR_SZ, MEMORY_START, STORAGE_SZ,
                       STORAGE_START, STORAGE_PTR_SZ, EXT_ADDR_SZ)

EVMCallNr = {
    "CALL": 0,
    "CALLCODE": 1,
    "DELEGATECALL": 2,
    "CALLDATALOAD": 3,
    "CALLDATACOPY": 4,
    "CREATE": 5,
    "LOG": 6,
    "SUICIDE": 7,
    "BLOCKHASH": 8,
    "BALANCE": 9,
    "RETURN": 10,
    "REVERT": 11,
    "STOP": 12,
}


def evm_call(il, name, args=0, rets=0, noret=False):

    # TODO: this is shown as "constant" besides the normal EVM assembly
    # instruction. This is only internal to LLIL and not very pretty in the
    # resulting diassembly...
    il.append(
        il.set_reg(ADDR_SZ, "evm_call_nr", il.const(ADDR_SZ, EVMCallNr[name])))
    if args:
        for i in range(args):
            val = il.pop(ADDR_SZ)
            sreg = il.set_reg(ADDR_SZ, 'evm_call_arg' + str(i), val)
            il.append(sreg)

    if noret:
        # il.append(il.trap(EVMCallNr[name]))
        il.append(il.system_call())
        il.append(il.no_ret())
    else:
        il.append(il.system_call())
    if rets:
        for i in range(rets):
            # TODO: need to find a way that tells binary ninja that the
            # evm_call_ret0 register is written by the syscall instruction
            # il.append(il.push(ADDR_SZ, il.reg(ADDR_SZ, 'evm_call_ret0')))

            il.append(il.push(ADDR_SZ, il.unimplemented()))
    return None


def log(il, a):
    evm_call(il, "LOG", a + 2)
    return None


def cond_branch(il, addr):

    t = LowLevelILLabel()

    if addr is None:
        f = LowLevelILLabel()
    else:
        f = il.get_label_for_address(Architecture['evm'], addr + 1)
        if f is None:
            f = LowLevelILLabel()

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the
    # condition's il.pop(ADDR_SZ) first, but dest needs to be first.
    dest = il.pop(ADDR_SZ)
    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(0), dest))
    cond = il.pop(ADDR_SZ)
    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(1), cond))
    cond = il.compare_equal(ADDR_SZ, il.reg(ADDR_SZ, LLIL_TEMP(1)),
                            il.const(ADDR_SZ, 0))
    # cond = il.compare_equal(ADDR_SZ, il.pop(ADDR_SZ),
    #                         il.const(ADDR_SZ, 0))

    il.append(il.if_expr(cond, t, f))

    il.mark_label(t)
    il.append(il.jump(il.reg(ADDR_SZ, LLIL_TEMP(0))))

    il.mark_label(f)
    # false is the fall through case
    return None


def label(il, addr):
    f = il.get_label_for_address(Architecture['evm'], addr)
    if f is None:
        f = LowLevelILLabel()
    il.append(il.nop())
    il.mark_label(f)


def dup(il, a):
    assert a <= 16, "invalid DUP instruction"

    # DUP1 does s'[0] = s[0] according to the yellow paper
    # so a - 1 for DUP1 is 1 - 1 = 0 is the top of the stack
    a_addr = il.add(ADDR_SZ, il.reg(ADDR_SZ, 'sp'),
                    il.const(ADDR_SZ, (a - 1) * ADDR_SZ))
    a_value = il.load(ADDR_SZ, a_addr)
    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(0), a_value))
    il.append(il.push(ADDR_SZ, il.reg(ADDR_SZ, LLIL_TEMP(0))))
    return None


def swap(il, a):
    assert a <= 16, "invalid SWAP instruction"

    sp = il.reg(ADDR_SZ, 'sp')

    a_addr = il.add(ADDR_SZ, sp, il.const(ADDR_SZ, (a) * ADDR_SZ))
    b_addr = sp

    # Save the old a value into a temporary register
    a_val = il.load(ADDR_SZ, a_addr)
    a_reg = LLIL_TEMP(0)
    il.append(il.set_reg(ADDR_SZ, a_reg, a_val))
    b_val = il.load(ADDR_SZ, b_addr)

    # Copy b to a - overwriting a
    il.append(il.store(ADDR_SZ, a_addr, b_val))

    # Store old a to b
    il.append(il.store(ADDR_SZ, b_addr, il.reg(ADDR_SZ, a_reg)))

    return None


# TODO: implement exp opcode here
def exp(il, a, b):
    """compute a**b in a LLIL loop"""

    # TODO: mr: to be honest - I'm not sure this is really a good idea. This
    # might result in loooooong analysis times...
    # Anyone wanna do square-and-multiply? ;)

    # maybe we should try to do get a constant first?

    # used to return the value - return register
    retreg = LLIL_TEMP(2)
    # loop counter - count register
    creg = LLIL_TEMP(3)

    const1 = il.const(ADDR_SZ, 1)

    # base = s[0]
    base = il.pop(ADDR_SZ)
    basereg = LLIL_TEMP(0)
    il.append(il.set_reg(ADDR_SZ, basereg, base))

    # exponent = s[1]
    exponent = il.pop(ADDR_SZ)
    expreg = LLIL_TEMP(1)
    il.append(il.set_reg(ADDR_SZ, expreg, exponent))

    # labels
    loop_check = LowLevelILLabel()
    loop_body = LowLevelILLabel()
    loop_exit = LowLevelILLabel()

    # res = 1
    il.append(il.set_reg(ADDR_SZ, retreg, 1))
    # while count < exponent
    il.mark_label(loop_check)
    cond = il.compare_unsigned_less_than(ADDR_SZ, creg, expreg)
    il.append(il.if_expr(cond, loop_body, loop_exit))
    # loop
    il.mark_label(loop_body)
    # res = res * base
    b = il.mult(ADDR_SZ, retreg, basereg)
    il.append(il.set_reg(ADDR_SZ, retreg, b))
    # count += 1
    il.append(il.set_reg(ADDR_SZ, creg, il.add(ADDR_SZ, creg, const1)))
    # goto loop_check
    il.append(il.goto(loop_check))

    # break
    il.mark_label(loop_exit)
    # last step: push result to stack
    il.append(il.push(ADDR_SZ, retreg))
    return None


def byte(il):
    """extract the n-th byte from left in big-endian"""
    # used to return the value
    retreg = LLIL_TEMP(2)

    # th = s[0]
    th = il.pop(ADDR_SZ)
    threg = LLIL_TEMP(0)
    il.append(il.set_reg(ADDR_SZ, threg, th))

    # val = s[1]
    valreg = LLIL_TEMP(1)
    val = il.pop(ADDR_SZ)
    il.append(il.set_reg(ADDR_SZ, valreg, val))

    # if th >= 32:
    ret0 = LowLevelILLabel()
    other = LowLevelILLabel()
    const32 = il.const(ADDR_SZ, 32)
    ret0cond = il.compare_unsigned_greater_equal(threg, const32)
    il.append(il.if_expr(ret0cond, ret0, other))

    # then 0
    il.mark_label(ret0)
    const0 = il.const(ADDR_SZ, 0)
    il.append(il.set_reg(ADDR_SZ, retreg, const0))

    # else (val >> ((31 - th) * 8)) & 0xff
    il.mark_label(other)
    const8 = il.const(ADDR_SZ, 8)
    # shiftval = (31 - th) * 8
    shiftval = il.mul(ADDR_SZ, il.sub(ADDR_SZ, const32, threg), const8)
    # shifted = val >> shiftval
    shifted = il.logical_shift_right(ADDR_SZ, valreg, shiftval)
    # anded = shifted & 0xff
    constff = il.const(ADDR_SZ, 0xff)
    anded = il.and_expr(ADDR_SZ, shifted, constff)
    # return anded
    il.append(il.set_reg(ADDR_SZ, retreg, anded))

    il.append(il.push(ADDR_SZ, retreg))
    return None


def mstore(il, store_sz=32):
    # TODO: optimize later
    # this is a rather lengthy lifting of mstore. e.g. the scratch register
    # could be inlined. However, this way it is easier to debug.

    # temp0 = s[0] = index
    index = LLIL_TEMP(0)
    il.append(il.set_reg(ADDR_SZ, index, il.pop(ADDR_SZ)))
    # temp1 = s[1] = value
    value = LLIL_TEMP(1)
    il.append(il.set_reg(ADDR_SZ, value, il.pop(ADDR_SZ)))
    scratch = LLIL_TEMP(2)

    # TODO: this fails because binary ninja cannot handle a MEMORY_START larger
    # than 2**64-1 -- for now MEMORY_START is smaller
    il.append(
        il.set_reg(MEMORY_PTR_SZ, scratch,
                   il.add(MEMORY_PTR_SZ, il.const(MEMORY_PTR_SZ, MEMORY_START),
                          il.reg(MEMORY_PTR_SZ, index))))
    il.append(
        il.store(store_sz, il.reg(MEMORY_PTR_SZ, scratch),
                 il.reg(ADDR_SZ, value)))
    return None


def mload(il):
    # TODO: optimize later -- see mstore

    # temp0 = s[0] = index
    index = LLIL_TEMP(0)
    il.append(il.set_reg(ADDR_SZ, index, il.pop(ADDR_SZ)))

    scratch = LLIL_TEMP(2)
    il.append(
        il.set_reg(MEMORY_PTR_SZ, scratch,
                   il.add(MEMORY_PTR_SZ, il.const(MEMORY_PTR_SZ, MEMORY_START),
                          il.reg(MEMORY_PTR_SZ, index))))
    il.append(
        il.push(ADDR_SZ, il.load(ADDR_SZ, il.reg(MEMORY_PTR_SZ, scratch))))
    return None


def return_reg(name):
    return (lambda il, addr, operand, operand_size, pops, pushes:
            il.push(ADDR_SZ, il.reg(ADDR_SZ, name)))


InstructionIL = {
    'ADD': lambda il, addr, operand, operand_size, pops, pushes: [
        # il.push(ADDR_SZ, il.add(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ))),
        il.set_reg(ADDR_SZ, LLIL_TEMP(0), il.pop(ADDR_SZ)),
        il.set_reg(ADDR_SZ, LLIL_TEMP(1), il.pop(ADDR_SZ)),
        il.push(ADDR_SZ, il.add(ADDR_SZ,
                                il.reg(ADDR_SZ, LLIL_TEMP(0)),
                                il.reg(ADDR_SZ, LLIL_TEMP(1)))),
    ],
    'ADDRESS': return_reg("address"),
    'ADDMOD': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.mod_unsigned(ADDR_SZ,
                                il.add(ADDR_SZ,
                                       il.pop(ADDR_SZ),
                                       il.pop(ADDR_SZ)),
                                il.pop(ADDR_SZ)))
    ],
    'ALL_PUSH': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.const(ADDR_SZ, operand))
    ],
    # 'ALL_DUP': lambda il, addr, operand, operand_size, pops, pushes: [
    #     dup(il, operand_size)
    # ],
    'ALL_LOG': (lambda il, addr, operand, operand_size, pops, pushes:
                log(il, operand_size)),
    'AND': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.and_expr(ADDR_SZ,
                                     il.pop(ADDR_SZ),
                                     il.pop(ADDR_SZ)))
    ],
    'BALANCE': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'BALANCE', 1, 1),
    ],
    'BYTE': lambda il, addr, operand, operand_size, pops, pushes: byte(il),
    'BLOCKHASH': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'BLOCKHASH', 1, 1),
    ],
    'CALL': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'CALL', 7, 1),
    ],
    'CALLCODE': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'CALLCODE', 7, 1),
    ],
    'CALLDATASIZE': return_reg("calldatasize"),
    'CALLDATAVALUE': return_reg("calldatavalue"),
    'CALLDATALOAD': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'CALLDATALOAD', 1, 1),
    ],
    'CALLDATACOPY': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'CALLDATACOPY', 3, 0),
    ],
    'CALLER': return_reg("caller"),
    'CALLVALUE': return_reg("callvalue"),
    'CREATE': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'CREATE', 3, 1),
    ],
    'COINBASE': return_reg('coinbase'),
    'CODESIZE': lambda il, addr, operand, operand_size, pops, pushes: [
        # TODO: get the actual code-size - this creates a dependency between
        # this dictionary and the binaryview...
        il.push(ADDR_SZ, il.unimplemented())
    ],
    'CODECOPY': lambda il, addr, operand, operand_size, pops, pushes: [
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        # TODO: copy code-bytes to memory
        il.unimplemented(),
    ],
    'DIV': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.div_unsigned(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'DIFFICULTY': return_reg('difficulty'),
    'DELEGATECALL': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, 'DELEGATECALL', 6, 1),
    ],
    'EQ': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.compare_equal(ADDR_SZ,
                                 il.pop(ADDR_SZ),
                                 il.pop(ADDR_SZ)))
    ],
    'EXP': lambda il, addr, operand, operand_size, pops, pushes: [
        il.set_reg(ADDR_SZ, LLIL_TEMP(0), il.pop(ADDR_SZ)),
        il.set_reg(ADDR_SZ, LLIL_TEMP(1), il.pop(ADDR_SZ)),
        exp(il, il.reg(ADDR_SZ, LLIL_TEMP(0)), il.reg(ADDR_SZ, LLIL_TEMP(1))),
    ],
    'EXTCODESIZE': lambda il, addr, operand, operand_size, pops, pushes: [
        il.pop(ADDR_SZ),
        il.push(ADDR_SZ, il.unimplemented())
    ],
    'EXTCODECOPY': lambda il, addr, operand, operand_size, pops, pushes: [
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        il.unimplemented(),
    ],
    'JUMP': lambda il, addr, operand, operand_size, pops, pushes: [
        # il.jump(il.pop(ADDR_SZ)),
        il.set_reg(ADDR_SZ, LLIL_TEMP(0), il.pop(ADDR_SZ)),
        il.jump(il.reg(ADDR_SZ, LLIL_TEMP(0))),
    ],
    'JUMPDEST': lambda il, addr, operand, operand_size, pops, pushes: [
        label(il, addr),
    ],
    'JUMPI': lambda il, addr, operand, operand_size, pops, pushes: [
        cond_branch(il, operand)
    ],
    'GAS': return_reg('gas_available'),
    'GASPRICE': return_reg('gasprice'),
    'GASLIMIT': return_reg('gaslimit'),
    'GT': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.compare_unsigned_greater_than(ADDR_SZ,
                                                 il.pop(ADDR_SZ),
                                                 il.pop(ADDR_SZ)))
    ],
    'INVALID': (lambda il, addr, operand, operand_size, pops, pushes:
                il.no_ret()),
    'ISZERO': lambda il, addr, operand, operand_size, pops, pushes: [
        # logical NOT, not bitwise: i.e. returns always 0 or 1
        il.set_reg(ADDR_SZ, LLIL_TEMP(0), il.pop(ADDR_SZ)),
        il.push(ADDR_SZ,
                il.and_expr(ADDR_SZ,
                            il.not_expr(ADDR_SZ,
                                        il.reg(ADDR_SZ, LLIL_TEMP(0))),
                            il.const(ADDR_SZ, 1))),
    ],
    'RETURN': lambda il, addr, operand, operand_size, pops, pushes: [
        # return is the end - but it's not the same as a traditional return, it
        # basically returns to another address space. We model this as a LLIL
        # trap.
        evm_call(il, "RETURN", 2, 0, True)
    ],
    'REVERT': (lambda il, addr, operand, operand_size, pops, pushes:
               evm_call(il, 'REVERT', 2, 0, True)),
    'SDIV': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.div_signed(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'SIGNEXTEND': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.sign_extedn(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ))),
    ],
    'SLT': lambda il, addr, operand, operand_size, pops, pushes: [
        # whitepaper: s[0] < s[1]
        # LLIL: compare_signed_less_than(size, a, b) => a < b
        il.push(ADDR_SZ,
                il.compare_signed_less_than(ADDR_SZ,
                                            # s[0] = a
                                            il.pop(ADDR_SZ),
                                            # s[1] = b
                                            il.pop(ADDR_SZ)))
    ],
    'SGT': lambda il, addr, operand, operand_size, pops, pushes: [
        # whitepaper: s[0] > s[1]
        il.push(ADDR_SZ,
                il.compare_signed_greater_than(ADDR_SZ,
                                               il.pop(ADDR_SZ),
                                               il.pop(ADDR_SZ)))
    ],
    'SMOD': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.mod_signed(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'STOP': (lambda il, addr, operand, operand_size, pops, pushes:
             evm_call(il, 'STOP', 0, 0, True)),
    # 'ALL_SWAP': lambda il, addr, operand, operand_size, pops, pushes: [
    #     swap(il, 1, operand_size + 1),
    # ],
    'SUB': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.sub(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ))),
    ],
    'SUICIDE': lambda il, addr, operand, operand_size, pops, pushes: [
        evm_call(il, "SUICIDE", 1, 0, True)
    ],
    'SSTORE': lambda il, addr, operand, operand_size, pops, pushes: [
        # il.store(ADDR_SZ,
        #          il.add(STORAGE_PTR_SZ,
        #                 il.pop(ADDR_SZ),
        #                 il.const(STORAGE_PTR_SZ, STORAGE_START)),
        #          il.pop(ADDR_SZ))
        il.pop(ADDR_SZ),
        il.pop(ADDR_SZ),
        il.unimplemented(),
    ],
    'SLOAD': lambda il, addr, operand, operand_size, pops, pushes: [
        # il.load(ADDR_SZ,
        #         il.add(STORAGE_PTR_SZ,
        #                il.pop(ADDR_SZ),
        #                il.const(STORAGE_PTR_SZ, STORAGE_START)))
        il.pop(ADDR_SZ),
        il.unimplemented(),
        il.push(ADDR_SZ, il.unimplemented()),
    ],
    'SHA3': lambda il, addr, operand, operand_size, pops, pushes: [
        # UNDEFINED
        il.pop(ADDR_SZ),  # s[0]
        il.pop(ADDR_SZ),  # s[1]
        il.unimplemented(),
        il.push(ADDR_SZ, il.unimplemented()),
        # TODO: implement SHA3 in LLIL? jk...
    ],
    'TIMESTAMP': return_reg('timestamp'),
    'LT': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.compare_unsigned_less_than(ADDR_SZ,
                                              il.pop(ADDR_SZ),
                                              il.pop(ADDR_SZ)))
    ],
    'MOD': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.mod_unsigned(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'MSTORE': lambda il, addr, operand, operand_size, pops, pushes: [
        mstore(il),
    ],
    'MSTORE8': lambda il, addr, operand, operand_size, pops, pushes: [
        mstore(il, 8),
    ],
    'MLOAD': lambda il, addr, operand, operand_size, pops, pushes: [
        mload(il),
    ],
    'MUL': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.mult(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'MULMOD': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.mod_unsigned(ADDR_SZ,
                                il.mult(ADDR_SZ,
                                        il.pop(ADDR_SZ),
                                        il.pop(ADDR_SZ)),
                                il.pop(ADDR_SZ)))
    ],
    'NOT': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.not_expr(ADDR_SZ, il.pop(ADDR_SZ)))
    ],
    'NUMBER': return_reg('number'),
    'OR': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ, il.or_expr(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'ORIGIN': return_reg("origin"),
    'PC': return_reg("pc"),
    # 'POP': (lambda il, addr, operand, operand_size, pops, pushes:
    #         il.pop(ADDR_SZ)),
    'POP': (lambda il, addr, operand, operand_size, pops, pushes:
            il.pop(ADDR_SZ)),
    'XOR': lambda il, addr, operand, operand_size, pops, pushes: [
        il.push(ADDR_SZ,
                il.xor_expr(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
    ],
    'SELFDESTRUCT': (lambda il, addr, operand, operand_size, pops, pushes:
                     il.no_ret()),
    # swaps
    'SWAP1': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 1)),
    'SWAP2': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 2)),
    'SWAP3': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 3)),
    'SWAP4': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 4)),
    'SWAP5': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 5)),
    'SWAP6': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 6)),
    'SWAP7': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 7)),
    'SWAP8': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 8)),
    'SWAP9': (lambda il, addr, operand, operand_size, pops, pushes:
              swap(il, 9)),
    'SWAP10': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 10)),
    'SWAP11': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 11)),
    'SWAP12': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 12)),
    'SWAP13': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 13)),
    'SWAP14': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 14)),
    'SWAP15': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 15)),
    'SWAP16': (lambda il, addr, operand, operand_size, pops, pushes:
               swap(il, 16)),

    # dups
    'DUP1': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 1)),
    'DUP2': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 2)),
    'DUP3': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 3)),
    'DUP4': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 4)),
    'DUP5': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 5)),
    'DUP6': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 6)),
    'DUP7': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 7)),
    'DUP8': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 8)),
    'DUP9': (lambda il, addr, operand, operand_size, pops, pushes:
             dup(il, 9)),
    'DUP10': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 10)),
    'DUP11': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 11)),
    'DUP12': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 12)),
    'DUP13': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 13)),
    'DUP14': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 14)),
    'DUP15': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 15)),
    'DUP16': (lambda il, addr, operand, operand_size, pops, pushes:
              dup(il, 16)),
}

# the following commented-out code had a very strange side-effect: something
# with the closures would be f'ed up, such that 'i' would always eval to the
# last 'i' in the loop...

# for i in range(1, 17):
#     dupopn = "DUP" + str(i)
#     InstructionIL[dupopn] = (
#         lambda il, addr, operand, operand_size, pops, pushes: dup(il, i))

# for i in range(1, 17):
#     swapopn = "SWAP" + str(i)
#     InstructionIL[swapopn] = (
#         lambda il, addr, operand, operand_size, pops, pushes: swap(il, i))
