'''
    Code from manticore
'''

# from http://gavwood.com/paper.pdf
OPCODE_TABLE = {
    # opcode: (name, immediate_operand_size, pops, pushes, description)
    0x00: ('STOP', 0, 0, 0, 'Halts execution.'),
    0x01: ('ADD', 0, 2, 1, 'Addition operation.'),
    0x02: ('MUL', 0, 2, 1, 'Multiplication operation.'),
    0x03: ('SUB', 0, 2, 1, 'Subtraction operation.'),
    0x04: ('DIV', 0, 2, 1, 'Integer division operation.'),
    0x05: ('SDIV', 0, 2, 1, 'Signed integer division operation (truncated).'),
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
    0x30: ('ADDRESS', 0, 0, 1, 'Get address of currently executing account.'),
    0x31: ('BALANCE', 0, 1, 1, 'Get balance of the given account.'),
    0x32: ('ORIGIN', 0, 0, 1, 'Get execution origination address.'),
    0x33: ('CALLER', 0, 0, 1, 'Get caller address.'),
    0x34: ('CALLVALUE', 0, 0, 1,
           ('Get deposited value by the instruction/transaction '
            'responsible for this execution.')),
    0x35: ('CALLDATALOAD', 0, 1, 1, 'Get input data of current environment.'),
    0x36: ('CALLDATASIZE', 0, 0, 1,
           'Get size of input data in current environment.'),
    0x37: ('CALLDATACOPY', 0, 3, 0,
           'Copy input data in current environment to memory.'),
    0x38: ('CODESIZE', 0, 0, 1,
           'Get size of code running in current environment.'),
    0x39: ('CODECOPY', 0, 3, 0,
           'Copy code running in current environment to memory.'),
    0x3a: ('GASPRICE', 0, 0, 1, 'Get price of gas in current environment.'),
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
    0x60: ('PUSH', 1, 0, 1, 'Place 1 byte item on stack.'),
    0x61: ('PUSH', 2, 0, 1, 'Place 2-byte item on stack.'),
    0x62: ('PUSH', 3, 0, 1, 'Place 3-byte item on stack.'),
    0x63: ('PUSH', 4, 0, 1, 'Place 4-byte item on stack.'),
    0x64: ('PUSH', 5, 0, 1, 'Place 5-byte item on stack.'),
    0x65: ('PUSH', 6, 0, 1, 'Place 6-byte item on stack.'),
    0x66: ('PUSH', 7, 0, 1, 'Place 7-byte item on stack.'),
    0x67: ('PUSH', 8, 0, 1, 'Place 8-byte item on stack.'),
    0x68: ('PUSH', 9, 0, 1, 'Place 9-byte item on stack.'),
    0x69: ('PUSH', 10, 0, 1, 'Place 10-byte item on stack.'),
    0x6a: ('PUSH', 11, 0, 1, 'Place 11-byte item on stack.'),
    0x6b: ('PUSH', 12, 0, 1, 'Place 12-byte item on stack.'),
    0x6c: ('PUSH', 13, 0, 1, 'Place 13-byte item on stack.'),
    0x6d: ('PUSH', 14, 0, 1, 'Place 14-byte item on stack.'),
    0x6e: ('PUSH', 15, 0, 1, 'Place 15-byte item on stack.'),
    0x6f: ('PUSH', 16, 0, 1, 'Place 16-byte item on stack.'),
    0x70: ('PUSH', 17, 0, 1, 'Place 17-byte item on stack.'),
    0x71: ('PUSH', 18, 0, 1, 'Place 18-byte item on stack.'),
    0x72: ('PUSH', 19, 0, 1, 'Place 19-byte item on stack.'),
    0x73: ('PUSH', 20, 0, 1, 'Place 20-byte item on stack.'),
    0x74: ('PUSH', 21, 0, 1, 'Place 21-byte item on stack.'),
    0x75: ('PUSH', 22, 0, 1, 'Place 22-byte item on stack.'),
    0x76: ('PUSH', 23, 0, 1, 'Place 23-byte item on stack.'),
    0x77: ('PUSH', 24, 0, 1, 'Place 24-byte item on stack.'),
    0x78: ('PUSH', 25, 0, 1, 'Place 25-byte item on stack.'),
    0x79: ('PUSH', 26, 0, 1, 'Place 26-byte item on stack.'),
    0x7a: ('PUSH', 27, 0, 1, 'Place 27-byte item on stack.'),
    0x7b: ('PUSH', 28, 0, 1, 'Place 28-byte item on stack.'),
    0x7c: ('PUSH', 29, 0, 1, 'Place 29-byte item on stack.'),
    0x7d: ('PUSH', 30, 0, 1, 'Place 30-byte item on stack.'),
    0x7e: ('PUSH', 31, 0, 1, 'Place 31-byte item on stack.'),
    0x7f: ('PUSH', 32, 0, 1, 'Place 32-byte (full word) item on stack.'),
    0x80: ('DUP', 0, 1, 2, 'Duplicate 1st stack item.'),
    0x81: ('DUP', 0, 2, 3, 'Duplicate 2nd stack item.'),
    0x82: ('DUP', 0, 3, 4, 'Duplicate 3rd stack item.'),
    0x83: ('DUP', 0, 4, 5, 'Duplicate 4th stack item.'),
    0x84: ('DUP', 0, 5, 6, 'Duplicate 5th stack item.'),
    0x85: ('DUP', 0, 6, 7, 'Duplicate 6th stack item.'),
    0x86: ('DUP', 0, 7, 8, 'Duplicate 7th stack item.'),
    0x87: ('DUP', 0, 8, 9, 'Duplicate 8th stack item.'),
    0x88: ('DUP', 0, 9, 10, 'Duplicate 9th stack item.'),
    0x89: ('DUP', 0, 10, 11, 'Duplicate 10th stack item.'),
    0x8a: ('DUP', 0, 11, 12, 'Duplicate 11th stack item.'),
    0x8b: ('DUP', 0, 12, 13, 'Duplicate 12th stack item.'),
    0x8c: ('DUP', 0, 13, 14, 'Duplicate 13th stack item.'),
    0x8d: ('DUP', 0, 14, 15, 'Duplicate 14th stack item.'),
    0x8e: ('DUP', 0, 15, 16, 'Duplicate 15th stack item.'),
    0x8f: ('DUP', 0, 16, 17, 'Duplicate 16th stack item.'),
    0x90: ('SWAP', 0, 2, 2, 'Exchange 1st and 2nd stack items.'),
    0x91: ('SWAP', 0, 3, 3, 'Exchange 1st and 3rd stack items.'),
    0x92: ('SWAP', 0, 4, 4, 'Exchange 1st and 4rd stack items.'),
    0x93: ('SWAP', 0, 5, 5, 'Exchange 1st and 5rd stack items.'),
    0x94: ('SWAP', 0, 6, 6, 'Exchange 1st and 6rd stack items.'),
    0x95: ('SWAP', 0, 7, 7, 'Exchange 1st and 7rd stack items.'),
    0x96: ('SWAP', 0, 8, 8, 'Exchange 1st and 8rd stack items.'),
    0x97: ('SWAP', 0, 9, 9, 'Exchange 1st and 9rd stack items.'),
    0x98: ('SWAP', 0, 10, 10, 'Exchange 1st and 10rd stack items.'),
    0x99: ('SWAP', 0, 11, 11, 'Exchange 1st and 11rd stack items.'),
    0x9a: ('SWAP', 0, 12, 12, 'Exchange 1st and 12rd stack items.'),
    0x9b: ('SWAP', 0, 13, 13, 'Exchange 1st and 13rd stack items.'),
    0x9c: ('SWAP', 0, 14, 14, 'Exchange 1st and 14rd stack items.'),
    0x9d: ('SWAP', 0, 15, 15, 'Exchange 1st and 15rd stack items.'),
    0x9e: ('SWAP', 0, 16, 16, 'Exchange 1st and 16rd stack items.'),
    0x9f: ('SWAP', 0, 17, 17, 'Exchange 1st and 17th stack items.'),
    0xa0: ('LOG', 0, 2, 0, 'Append log record with no topics.'),
    0xa1: ('LOG', 0, 3, 0, 'Append log record with one topic.'),
    0xa2: ('LOG', 0, 4, 0, 'Append log record with two topics.'),
    0xa3: ('LOG', 0, 5, 0, 'Append log record with three topics.'),
    0xa4: ('LOG', 0, 6, 0, 'Append log record with four topics.'),
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
    0xfc: ('TXEXECGAS', 0, 0, 1, 'Not in yellow paper FIXME'),
    0xfd: ('REVERT', 0, 2, 0,
           ('Stop execution and revert state changes, without consuming '
            'all provided gas and providing a reason.')),
    0xfe: ('INVALID', 0, 0, 0, 'Designated invalid instruction.'),
    0xff: ('SELFDESTRUCT', 0, 1, 0,
           'Halt execution and register account for later deletion.')
}


OP = {}
for bytecode, info in OPCODE_TABLE.iteritems():
    opcode = info[0]
    OP[opcode] = bytecode
locals().update(OP)


class EVMInstruction(object):
    '''This represents an EVM instruction '''

    def __init__(self,
                 opcode,
                 name,
                 operand_size,
                 pops,
                 pushes,
                 description,
                 operand=None):
        self._opcode = opcode
        self._name = name
        self._operand_size = operand_size
        self._pops = pops
        self._pushes = pushes
        self._description = description
        self._operand = operand  # Immediate operand if any

    def parse_operand(self, buf):
        operand = 0
        for _ in range(self.operand_size):
            operand <<= 8
            try:
                operand |= ord(next(buf))
            except StopIteration:
                break
        self._operand = operand

    @property
    def operand_size(self):
        return self._operand_size

    @property
    def has_operand(self):
        return self.operand_size > 0

    @property
    def operand(self):
        return self._operand

    @property
    def pops(self):
        return self._pops

    @property
    def pushes(self):
        return self._pushes

    @property
    def size(self):
        return self._operand_size + 1

    def __len__(self):
        return self.size

    @property
    def name(self):
        if self._name == 'PUSH':
            return 'PUSH%d' % self.operand_size
        elif self._name == 'DUP':
            return 'DUP%d' % self.pops
        elif self._name == 'SWAP':
            return 'SWAP%d' % (self.pops - 1)
        elif self._name == 'LOG':
            return 'LOG%d' % (self.pops - 2)
        return self._name

    def __str__(self):
        bytes = self.bytes.encode('hex')

        output = '<%s> ' % bytes + self.name
        output += (' 0x%x' % self.operand if self.has_operand else '')
        if True:
            output += ' ' * (80 - len(output)) + self.description
        return output

    @property
    def semantics(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def bytes(self):
        bytes = []
        bytes.append(chr(self._opcode))
        for offset in reversed(xrange(self.operand_size)):
            c = (self.operand >> offset * 8) & 0xff
            bytes.append(chr(c))
        return ''.join(bytes)


class EVMDecoder(object):
    '''
        EVM Instruction factory
    '''
    _table = OPCODE_TABLE

    @staticmethod
    def decode_one(bytecode):
        '''
        '''
        bytecode = iter(bytecode)
        opcode = ord(next(bytecode))
        invalid = ('INVALID', 0, 0, 0, 'Unknown opcode')
        name, operand_size, pops, pushes, description = (EVMDecoder._table.get(
            opcode, invalid))

        instruction = EVMInstruction(opcode, name, operand_size, pops, pushes,
                                     description)
        if instruction.has_operand:
            instruction.parse_operand(bytecode)

        return instruction

    @staticmethod
    def decode_all(bytecode):
        bytecode = iter(bytecode)
        while True:
            yield EVMDecoder.decode_one(bytecode)

    @staticmethod
    def disassemble(bytecode):
        output = ''
        address = 0
        for i in EVMDecoder.decode_all(bytecode):
            output += "0x%04x %s\n" % (address, i)
            address += i.size
        return output
