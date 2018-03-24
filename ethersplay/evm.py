#!/usr/bin/env python
# -*- coding: utf-8 -*-

from binaryninja import *

opcodes = {
    # opcode: (name, immediate_operand_size, pops, pushes, description)
    0x00: ('STOP', 0, 0, 0, 'Halts execution.'),
    0x01: ('ADD', 0, 2, 1, 'Addition operation.'),
    0x02: ('MUL', 0, 2, 1, 'Multiplication operation.'),
    0x03: ('SUB', 0, 2, 1, 'Subtraction operation.'),
    0x04: ('DIV', 0, 2, 1, 'Integer division operation.'),
    0x05: ('SDIV', 0, 2, 1,
           'Signed integer division operation (truncated).'),
    0x06: ('MOD', 0, 2, 1, 'Modulo remainder operation.'),
    0x07: ('SMOD', 0, 2, 1, 'Signed modulo remainder operation.'),
    0x08: ('ADDMOD', 0, 3, 1, 'Modulo addition operation.'),
    0x09: ('MULMOD', 0, 3, 1, 'Modulo multiplication operation.'),
    0x0a: ('EXP', 0, 2, 1, 'Exponential operation.'),
    0x0b: ('SIGNEXTEND', 0, 2, 1,
           'Extend length of two\'s complement signed integer.'),
    0x10: ('LT', 0, 2, 1, 'Less-than comparision.'),
    0x11: ('GT', 0, 2, 1, 'Greater-than comparision.'),
    0x12: ('SLT', 0, 2, 1, 'Signed less-than comparision.'),
    0x13: ('SGT', 0, 2, 1, 'Signed greater-than comparision.'),
    0x14: ('EQ', 0, 2, 1, 'Equality comparision.'),
    0x15: ('ISZERO', 0, 1, 1, 'Simple not operator.'),
    0x16: ('AND', 0, 2, 1, 'Bitwise AND operation.'),
    0x17: ('OR', 0, 2, 1, 'Bitwise OR operation.'),
    0x18: ('XOR', 0, 2, 1, 'Bitwise XOR operation.'),
    0x19: ('NOT', 0, 1, 1, 'Bitwise NOT operation.'),
    0x1a: ('BYTE', 0, 2, 1, 'Retrieve single byte from word.'),
    0x20: ('SHA3', 0, 2, 1, 'Compute Keccak-256 hash.'),
    0x30: ('ADDRESS', 0, 0, 1,
           'Get address of currently executing account.'),
    0x31: ('BALANCE', 0, 1, 1, 'Get balance of the given account.'),
    0x32: ('ORIGIN', 0, 0, 1, 'Get execution origination address.'),
    0x33: ('CALLER', 0, 0, 1, 'Get caller address.'),
    0x34: ('CALLVALUE', 0, 0, 1,
           ('Get deposited value by the instruction/transaction '
            'responsible for this execution.')),
    0x35: ('CALLDATALOAD', 0, 1, 1,
           'Get input data of current environment.'),
    0x36: ('CALLDATASIZE', 0, 0, 1,
           'Get size of input data in current environment.'),
    0x37: ('CALLDATACOPY', 0, 3, 0,
           'Copy input data in current environment to memory.'),
    0x38: ('CODESIZE', 0, 0, 1,
           'Get size of code running in current environment.'),
    0x39: ('CODECOPY', 0, 3, 0,
           'Copy code running in current environment to memory.'),
    0x3a: ('GASPRICE', 0, 0, 1,
           'Get price of gas in current environment.'),
    0x3b: ('EXTCODESIZE', 0, 1, 1, 'Get size of an account\'s code.'),
    0x3c: ('EXTCODECOPY', 0, 4, 0, 'Copy an account\'s code to memory.'),
    0x40: ('BLOCKHASH', 0, 1, 1,
           'Get the hash of one of the 256 most recent complete blocks.'),
    0x41: ('COINBASE', 0, 0, 1, 'Get the block\'s beneficiary address.'),
    0x42: ('TIMESTAMP', 0, 0, 1, 'Get the block\'s timestamp.'),
    0x43: ('NUMBER', 0, 0, 1, 'Get the block\'s number.'),
    0x44: ('DIFFICULTY', 0, 0, 1, 'Get the block\'s difficulty.'),
    0x45: ('GASLIMIT', 0, 0, 1, 'Get the block\'s gas limit.'),
    0x50: ('POP', 0, 1, 0, 'Remove item from stack.'),
    0x51: ('MLOAD', 0, 1, 1, 'Load word from memory.'),
    0x52: ('MSTORE', 0, 2, 0, 'Save word to memory.'),
    0x53: ('MSTORE8', 0, 2, 0, 'Save byte to memory.'),
    0x54: ('SLOAD', 0, 1, 1, 'Load word from storage.'),
    0x55: ('SSTORE', 0, 2, 0, 'Save word to storage.'),
    0x56: ('JUMP', 0, 1, 0, 'Alter the program counter.'),
    0x57: ('JUMPI', 0, 2, 0, 'Conditionally alter the program counter.'),
    0x58: ('GETPC', 0, 0, 1,
           'Get the value of the program counter prior to the increment.'),
    0x59: ('MSIZE', 0, 0, 1, 'Get the size of active memory in bytes.'),
    0x5a: ('GAS', 0, 0, 1,
           ('Get the amount of available gas, including the corresponding'
            'reduction the amount of available gas.')),
    0x5b: ('JUMPDEST', 0, 0, 0, 'Mark a valid destination for jumps.'),
    0x60: ('PUSH1', 1, 0, 1, 'Place 1 byte item on stack.'),
    0x61: ('PUSH2', 2, 0, 1, 'Place 2-byte item on stack.'),
    0x62: ('PUSH3', 3, 0, 1, 'Place 3-byte item on stack.'),
    0x63: ('PUSH4', 4, 0, 1, 'Place 4-byte item on stack.'),
    0x64: ('PUSH5', 5, 0, 1, 'Place 5-byte item on stack.'),
    0x65: ('PUSH6', 6, 0, 1, 'Place 6-byte item on stack.'),
    0x66: ('PUSH7', 7, 0, 1, 'Place 7-byte item on stack.'),
    0x67: ('PUSH8', 8, 0, 1, 'Place 8-byte item on stack.'),
    0x68: ('PUSH9', 9, 0, 1, 'Place 9-byte item on stack.'),
    0x69: ('PUSH10', 10, 0, 1, 'Place 10-byte item on stack.'),
    0x6a: ('PUSH11', 11, 0, 1, 'Place 11-byte item on stack.'),
    0x6b: ('PUSH12', 12, 0, 1, 'Place 12-byte item on stack.'),
    0x6c: ('PUSH13', 13, 0, 1, 'Place 13-byte item on stack.'),
    0x6d: ('PUSH14', 14, 0, 1, 'Place 14-byte item on stack.'),
    0x6e: ('PUSH15', 15, 0, 1, 'Place 15-byte item on stack.'),
    0x6f: ('PUSH16', 16, 0, 1, 'Place 16-byte item on stack.'),
    0x70: ('PUSH17', 17, 0, 1, 'Place 17-byte item on stack.'),
    0x71: ('PUSH18', 18, 0, 1, 'Place 18-byte item on stack.'),
    0x72: ('PUSH19', 19, 0, 1, 'Place 19-byte item on stack.'),
    0x73: ('PUSH20', 20, 0, 1, 'Place 20-byte item on stack.'),
    0x74: ('PUSH21', 21, 0, 1, 'Place 21-byte item on stack.'),
    0x75: ('PUSH22', 22, 0, 1, 'Place 22-byte item on stack.'),
    0x76: ('PUSH23', 23, 0, 1, 'Place 23-byte item on stack.'),
    0x77: ('PUSH24', 24, 0, 1, 'Place 24-byte item on stack.'),
    0x78: ('PUSH25', 25, 0, 1, 'Place 25-byte item on stack.'),
    0x79: ('PUSH26', 26, 0, 1, 'Place 26-byte item on stack.'),
    0x7a: ('PUSH27', 27, 0, 1, 'Place 27-byte item on stack.'),
    0x7b: ('PUSH28', 28, 0, 1, 'Place 28-byte item on stack.'),
    0x7c: ('PUSH29', 29, 0, 1, 'Place 29-byte item on stack.'),
    0x7d: ('PUSH30', 30, 0, 1, 'Place 30-byte item on stack.'),
    0x7e: ('PUSH31', 31, 0, 1, 'Place 31-byte item on stack.'),
    0x7f: ('PUSH32', 32, 0, 1, 'Place 32-byte (full word) item on stack.'),
    0x80: ('DUP1', 0, 1, 2, 'Duplicate 1st stack item.'),
    0x81: ('DUP2', 0, 2, 3, 'Duplicate 2nd stack item.'),
    0x82: ('DUP2', 0, 3, 4, 'Duplicate 3rd stack item.'),
    0x83: ('DUP3', 0, 4, 5, 'Duplicate 4th stack item.'),
    0x84: ('DUP4', 0, 5, 6, 'Duplicate 5th stack item.'),
    0x85: ('DUP5', 0, 6, 7, 'Duplicate 6th stack item.'),
    0x86: ('DUP6', 0, 7, 8, 'Duplicate 7th stack item.'),
    0x87: ('DUP7', 0, 8, 9, 'Duplicate 8th stack item.'),
    0x88: ('DUP8', 0, 9, 10, 'Duplicate 9th stack item.'),
    0x89: ('DUP9', 0, 10, 11, 'Duplicate 10th stack item.'),
    0x8a: ('DUP10', 0, 11, 12, 'Duplicate 11th stack item.'),
    0x8b: ('DUP11', 0, 12, 13, 'Duplicate 12th stack item.'),
    0x8c: ('DUP12', 0, 13, 14, 'Duplicate 13th stack item.'),
    0x8d: ('DUP13', 0, 14, 15, 'Duplicate 14th stack item.'),
    0x8e: ('DUP14', 0, 15, 16, 'Duplicate 15th stack item.'),
    0x8f: ('DUP15', 0, 16, 17, 'Duplicate 16th stack item.'),
    0x90: ('SWAP1', 0, 2, 2, 'Exchange 1st and 2nd stack items.'),
    0x91: ('SWAP2', 0, 3, 3, 'Exchange 1st and 3rd stack items.'),
    0x92: ('SWAP3', 0, 4, 4, 'Exchange 1st and 4rd stack items.'),
    0x93: ('SWAP4', 0, 5, 5, 'Exchange 1st and 5rd stack items.'),
    0x94: ('SWAP5', 0, 6, 6, 'Exchange 1st and 6rd stack items.'),
    0x95: ('SWAP6', 0, 7, 7, 'Exchange 1st and 7rd stack items.'),
    0x96: ('SWAP7', 0, 8, 8, 'Exchange 1st and 8rd stack items.'),
    0x97: ('SWAP8', 0, 9, 9, 'Exchange 1st and 9rd stack items.'),
    0x98: ('SWAP9', 0, 10, 10, 'Exchange 1st and 10rd stack items.'),
    0x99: ('SWAP10', 0, 11, 11, 'Exchange 1st and 11rd stack items.'),
    0x9a: ('SWAP11', 0, 12, 12, 'Exchange 1st and 12rd stack items.'),
    0x9b: ('SWAP12', 0, 13, 13, 'Exchange 1st and 13rd stack items.'),
    0x9c: ('SWAP13', 0, 14, 14, 'Exchange 1st and 14rd stack items.'),
    0x9d: ('SWAP14', 0, 15, 15, 'Exchange 1st and 15rd stack items.'),
    0x9e: ('SWAP15', 0, 16, 16, 'Exchange 1st and 16rd stack items.'),
    0x9f: ('SWAP16', 0, 17, 17, 'Exchange 1st and 17th stack items.'),
    0xa0: ('LOG1', 0, 2, 0, 'Append log record with no topics.'),
    0xa1: ('LOG2', 0, 3, 0, 'Append log record with one topic.'),
    0xa2: ('LOG3', 0, 4, 0, 'Append log record with two topics.'),
    0xa3: ('LOG4', 0, 5, 0, 'Append log record with three topics.'),
    0xa4: ('LOG5', 0, 6, 0, 'Append log record with four topics.'),
    0xf0: ('CREATE', 0, 3, 1, 'Create a new account with associated code.'),
    0xf1: ('CALL', 0, 7, 1, 'Message-call into an account.'),
    0xf2: ('CALLCODE', 0, 7, 1,
           ('Message-call into this account with alternative '
            'account\'s code.')),
    0xf3: ('RETURN', 0, 2, 0, 'Halt execution returning output data.'),
    0xf4: ('DELEGATECALL', 0, 7, 1,
           ('Message-call into this account with an alternative account\'s'
            ' code, but persisting into this account with an alternative '
            'account\'s code.')),
    0xf5: ('BREAKPOINT', 0, 0, 0, 'Not in yellow paper FIXME'),
    0xf6: ('RNGSEED', 0, 1, 1, 'Not in yellow paper FIXME'),
    0xf7: ('SSIZEEXT', 0, 2, 1, 'Not in yellow paper FIXME'),
    0xf8: ('SLOADBYTES', 0, 3, 0, 'Not in yellow paper FIXME'),
    0xf9: ('SSTOREBYTES', 0, 3, 0, 'Not in yellow paper FIXME'),
    0xfa: ('SSIZE', 0, 1, 1, 'Not in yellow paper FIXME'),
    0xfb: ('STATEROOT', 0, 1, 1, 'Not in yellow paper FIXME'),
    0xfc: ('TXEXECGAS',0 , 0, 1, 'Not in yellow paper FIXME'),
    0xfd: ('REVERT', 0, 2, 0,
           ('Stop execution and revert state changes, without consuming '
            'all provided gas and providing a reason.')),
    0xfe: ('INVALID', 0, 0, 0, 'Designated invalid instruction.'),
    0xff: ('SELFDESTRUCT', 0, 1, 0,
           'Halt execution and register account for later deletion.')
}

def jumpi(il, addr, imm):
    t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['EthVM'], addr+1)
    must_mark = False

    if f is None:
        f = LowLevelILLabel()
        must_mark = True

    # We need to use a temporary register here. The il.if_expr() helper function makes a tree and evaluates the
    #  condition's il.pop(32) first, but dest needs to be first.
    dest = il.pop(8)
    il.append(il.set_reg(8, LLIL_TEMP(addr), dest))

    # Use a condition register that is never assigned to to prevent any pruning
    # il.append(il.pop(8))
    # cond = il.compare_equal(8, il.reg(8, 'cond'), il.const(8, 0))

    il.append(il.if_expr(il.pop(8), t, f))

    il.mark_label(t)
    il.append(il.jump(il.reg(8, LLIL_TEMP(addr))))

    if must_mark:
        il.mark_label(f)
        # false is the fall through case
        il.append(il.jump(il.const(8, addr + 1)))

    return []

def dup(mnem, il, addr, imm):
    a = int(mnem[3:])

    for i in xrange(a):
        il.append(il.set_reg(8, LLIL_TEMP(i), il.pop(8)))

    for i in xrange(a, 0, -1):
        il.append(il.push(8, il.reg(8, LLIL_TEMP(i-1))))

    il.append(il.push(8, il.reg(8, LLIL_TEMP(a - 1))))

    return []

def swap(mnem, il, addr, imm):
    a = 0
    b = int(mnem[4:]) + 1

    for i in xrange(b-1):
        il.append(il.set_reg(8, LLIL_TEMP(i), il.pop(8)))

    il.append(il.set_reg(8, 'swap', il.pop(8)))
    il.append(il.push(8, il.reg(8, LLIL_TEMP(0))))

    for i in xrange(b - 1, 1, -1):
        il.append(il.push(8, il.reg(8, LLIL_TEMP(i-1))))

    il.append(il.push(8, il.reg(8, 'swap')))

    return []

def jump(il, addr, imm):
    dest = il.pop(8)
    il.append(il.set_reg(8, LLIL_TEMP(addr), dest))

    il.append(il.jump(il.reg(8, LLIL_TEMP(addr))))

    return []


insn_il = {
        'AND' : lambda il, addr, imm: il.push(8, il.and_expr(8, il.pop(8), il.pop(8))),
        'EQ' : lambda il, addr, imm: il.push(8, il.compare_equal(8, il.pop(8), il.pop(8))),
        'POP' : lambda il, addr, imm: il.pop(8), # pop
        'JUMP' : jump,
        'JUMPI' : jumpi,
        'PUSH1' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH2' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH3' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH4' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH5' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH6' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH7' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH8' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH9' : lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH10': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH11': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH12': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH13': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH14': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH15': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH16': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH17': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH18': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH19': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH20': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH21': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH22': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH23': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH24': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH25': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH26': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH27': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH28': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH29': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH30': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH31': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'PUSH32': lambda il, addr, imm: il.push(8, il.const(8, imm & 0xffffffffffffffff)),
        'DUP1' : lambda il, addr, imm: dup('DUP1', il, addr, imm),
        'DUP2' : lambda il, addr, imm: dup('DUP2', il, addr, imm),
        'DUP3' : lambda il, addr, imm: dup('DUP3', il, addr, imm),
        'DUP4' : lambda il, addr, imm: dup('DUP4', il, addr, imm),
        'DUP5' : lambda il, addr, imm: dup('DUP5', il, addr, imm),
        'DUP6' : lambda il, addr, imm: dup('DUP6', il, addr, imm),
        'DUP7' : lambda il, addr, imm: dup('DUP7', il, addr, imm),
        'DUP8' : lambda il, addr, imm: dup('DUP8', il, addr, imm),
        'DUP9' : lambda il, addr, imm: dup('DUP9', il, addr, imm),
        'DUP10' : lambda il, addr, imm: dup('DUP10', il, addr, imm),
        'DUP11' : lambda il, addr, imm: dup('DUP11', il, addr, imm),
        'DUP12' : lambda il, addr, imm: dup('DUP12', il, addr, imm),
        'DUP13' : lambda il, addr, imm: dup('DUP13', il, addr, imm),
        'DUP14' : lambda il, addr, imm: dup('DUP14', il, addr, imm),
        'DUP15' : lambda il, addr, imm: dup('DUP15', il, addr, imm),
        'DUP16' : lambda il, addr, imm: dup('DUP16', il, addr, imm),
        'SWAP1' : lambda il, addr, imm: swap('SWAP1', il, addr, imm),
        'SWAP2' : lambda il, addr, imm: swap('SWAP2', il, addr, imm),
        'SWAP3' : lambda il, addr, imm: swap('SWAP3', il, addr, imm),
        'SWAP4' : lambda il, addr, imm: swap('SWAP4', il, addr, imm),
        'SWAP5' : lambda il, addr, imm: swap('SWAP5', il, addr, imm),
        'SWAP6' : lambda il, addr, imm: swap('SWAP6', il, addr, imm),
        'SWAP7' : lambda il, addr, imm: swap('SWAP7', il, addr, imm),
        'SWAP8' : lambda il, addr, imm: swap('SWAP8', il, addr, imm),
        'SWAP9' : lambda il, addr, imm: swap('SWAP9', il, addr, imm),
        'SWAP10' : lambda il, addr, imm: swap('SWAP10', il, addr, imm),
        'SWAP11' : lambda il, addr, imm: swap('SWAP11', il, addr, imm),
        'SWAP12' : lambda il, addr, imm: swap('SWAP12', il, addr, imm),
        'SWAP13' : lambda il, addr, imm: swap('SWAP13', il, addr, imm),
        'SWAP14' : lambda il, addr, imm: swap('SWAP14', il, addr, imm),
        'SWAP15' : lambda il, addr, imm: swap('SWAP15', il, addr, imm),
        'SWAP16' : lambda il, addr, imm: swap('SWAP16', il, addr, imm),
        'STOP' : lambda il, addr, imm: il.no_ret(),
        'REVERT' : lambda il, addr, imm: il.no_ret(),
        'RETURN' : lambda il, addr, imm: il.ret(il.pop(8)),
        'INVALID' : lambda il, addr, imm: il.no_ret(),
        'SUICIDE' : lambda il, addr, imm: il.ret(il.pop(8)),
        'SELFDESTRUCT' : lambda il, addr, imm: il.ret(il.pop(8)),
}

class EVM(Architecture):
    name = "EthVM"
    address_size = 8 # Actual size is 32 but we're going to truncate everything
    default_int_size = 8 # should be 32
    instr_alignment = 1
    max_instr_length = 33
    regs = {
        "sp": RegisterInfo("sp", 8),
        "cond" : RegisterInfo("cond", 8), # condition register, never assigned to
        "swap" : RegisterInfo("swap", 8) # swap temporary
    }
    stack_pointer = "sp"

    def decode_instruction(self, data, addr):
        log_info("get_instruction_info")
        if len(data) < 1:
            return None, None, None, None, None
        opcode = ord(data[0])
        info = opcodes[opcode]
        if info is None:
            return None, None, None, None, None

        # opcode: (name, immediate_operand_size, pops, pushes, description)
        (mnem, additional, pops, pushes, _) = info

        length = 1 + additional
        operand = None
        immediate_value = None
        if additional > 0:
            operand = data[1:1+additional]

            immediate_value = ord(data[1])
            for i in xrange(1, additional):
                immediate_value <<= 8

                immediate_value |= ord(data[i + 1])

        return mnem, length, immediate_value, pops, pushes

    def perform_get_instruction_info(self, data, addr):
        log_info("get_instruction_info")
        mnem, length, imm, pops, pushes = self.decode_instruction(data, addr)
        if mnem is None:
            return None

        result = InstructionInfo()
        result.length = length
        if mnem == "JUMP":
            result.add_branch(BranchType.UnresolvedBranch)
        if mnem == "JUMPI":
            result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + 1)
        if mnem in ['RETURN', 'REVERT', 'SUICIDE', 'INVALID', 'STOP', 'SELFDESTRUCT']:
            result.add_branch(BranchType.FunctionReturn)

        return result

    def perform_get_instruction_text(self, data, addr):
        log_info("get_instruction_info")
        mnem, length, imm, pops, pushes = self.decode_instruction(data, addr)
        if mnem is None:
            return None

        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "%-7s " % mnem.replace("@", "")))

        if "PUSH" in mnem:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "#"))
            fmtstring = "%.0{0}x".format((length - 1) * 2)
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, fmtstring % imm, imm))

        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        log_info("get_instruction_low_level_il")
        mnem, length, imm, pops, pushes = self.decode_instruction(data, addr)
        if mnem is None:
            return None


        ill = insn_il.get(mnem, None)
        if ill is None:

            for i in xrange(pops):
                il.append(il.pop(8))

            for i in xrange(pushes):
                il.append(il.push(8, il.unimplemented()))

            return length

        ils = ill(il, addr, imm)
        if isinstance(ils, list):
            for i in ils:
                il.append(il)
        else:
            il.append(ils)

        return length


class EVMView(BinaryView):
    name = "EVM"
    long_name = "Ethereum Bytecode"

    def __init__(self, data):
       BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
       self.raw = data

    def init(self):
        self.arch = Architecture['EthVM']
        self.platform = Architecture['EthVM'].standalone_platform
        self.add_entry_point(0)

        file_size = len(self.raw)
        self.add_auto_segment(
            0, file_size-3, 3, file_size,
            (SegmentFlag.SegmentReadable |
            SegmentFlag.SegmentExecutable)
        )
        return True

    @classmethod
    def is_valid_for_data(self, data):
        file_header = data.read(0, 3)
        if file_header == 'EVM':
            return True
        return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

