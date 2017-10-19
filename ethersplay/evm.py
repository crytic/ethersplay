import traceback
import time
import threading

from binaryninja import *
from manticore_evm import *

from create_methods import CreateMethods
from print_known_hashes import HashMatcher
from stack_value_analysis import function_dynamic_jump_start

ADDR_SZ = 4

InstructionGas = {
    'STOP' : 0,
    'ADD' : 3,
    'MUL' : 5,
    'SUB' : 3,
    'DIV' : 2,
    'SDIV' : 5,
    'MOD' : 5,
    'SMOD' : 5,
    'ADDMOD' : 8,
    'MULMOD' : 8,
    'EXP' : 10,
    'SIGNEXTEND' : 5,
    'LT' : 3,
    'GT' : 3,
    'SLT' : 3,
    'SGT' : 3,
    'EQ' : 3,
    'ISZERO' : 3,
    'AND' : 3,
    'OR' : 3,
    'XOR' : 3,
    'NOT' : 3,
    'BYTE' : 3,
    'SHA3' : 30,
    'ADDRESS' : 2,
    'BALANCE' : 20,
    'ORIGIN' : 2,
    'CALLER' : 2,
    'CALLVALUE' : 2,
    'CALLDATALOAD' : 3,
    'CALLDATASIZE' : 2,
    'CALLDATACOPY' : 3,
    'CODESIZE' : 2,
    'CODECOPY' : 3,
    'GASPRICE' : 2,
    'EXTCODESIZE' : 20,
    'EXTCODECOPY' : 20,
    'BLOCKHASH' : 20,
    'COINBASE' : 2,
    'TIMESTAMP' : 2,
    'NUMBER' : 2,
    'DIFFICULTY' : 2,
    'GASLIMIT' : 2,
    'POP' : 2,
    'MLOAD' : 3,
    'MSTORE' : 3,
    'MSTORE8' : 3,
    'SLOAD' : 50,
    'SSTORE' : 0,
    'JUMP' : 8,
    'JUMPI' : 10,
    'PC' : 2,
    'MSIZE' : 2,
    'GAS' : 2,
    'JUMPDEST' : 1,
    'ALL_PUSH' : 3,
    'ALL_DUP' : 3,
    'ALL_SWAP': 3,
    'PUSH' : 1875,
    'DUP' : 1875,
    'SWAP' : 1875,
    'CREATE' : 32000,
    'CALL' : 40,
    'CALLCODE' : 40,
    'RETURN' : 0,
    'SELFDESTRUCT' : 0,
    'DELEGATECALL' : 40,
    'SUICIDE' : 0
}

# TODO: for now we remove the IL transformation

#def cond_branch(il, addr):
#
#    t = LowLevelILLabel()
#
#    if addr is None:
#        f = LowLevelILLabel()
#    else:
#        f = il.get_label_for_address(Architecture['evm'], addr + 1)
#        if f is None:
#            f = LowLevelILLabel()
#
#    # We need to use a temporary register here. The il.if_expr() helper
#    # function makes a tree and evaluates the
#    # condition's il.pop(ADDR_SZ) first, but dest needs to be first.
#    dest = il.pop(ADDR_SZ)
#    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(0), dest))
#
#    cond = il.compare_equal(ADDR_SZ, il.pop(ADDR_SZ), il.const(ADDR_SZ, 0))
#
#    il.append(il.if_expr(cond, t, f))
#
#    il.mark_label(t)
#    il.append(il.jump(il.reg(ADDR_SZ, LLIL_TEMP(0))))
#
#    il.mark_label(f)
#    # false is the fall through case
#    return None
#
#def label(il, addr):
#    f = il.get_label_for_address(Architecture['evm'], addr)
#    if f is None:
#        f = LowLevelILLabel()
#    il.append(il.nop())
#    il.mark_label(f)
#
#def dup(il, a):
#    a_addr = il.add(ADDR_SZ,
#                    il.reg(ADDR_SZ, 'sp'),
#                    il.const(ADDR_SZ, a * ADDR_SZ))
#    a_value = il.load(ADDR_SZ, a_addr)
#    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(0), a_value))
#    il.append(il.push(ADDR_SZ, il.reg(ADDR_SZ, LLIL_TEMP(0))))
#    return None
#

#def swap(il, a, b):
#    sp = il.reg(ADDR_SZ, 'sp')
#    a_addr = il.add(ADDR_SZ, sp, il.const(ADDR_SZ, (a - 1) * ADDR_SZ))
#    b_addr = il.add(ADDR_SZ, sp, il.const(ADDR_SZ, (b - 1) * ADDR_SZ))
#
#    # Save the old A value
#    old = il.load(ADDR_SZ, a_addr)
#    il.append(il.set_reg(ADDR_SZ, LLIL_TEMP(0), old))
#
#    # Copy b to a
#    il.append(il.store(ADDR_SZ, a_addr, il.load(ADDR_SZ, b_addr)))
#
#    # Store old a to b
#    il.append(il.store(ADDR_SZ, b_addr, il.reg(ADDR_SZ, LLIL_TEMP(0))))
#
#    return None

def gas(il, name):
    price = InstructionGas.get(name, 0)
    if price == 0:
        return
    il.append(il.set_reg(8,
                         'gas',
                         il.add(8, il.reg(8, 'gas'), il.const(8, price))))

# d: stack arguments required
# a: address
# FIXME a bunch of insn are wrong (e.g., MLOAD, MSTORE), also get side-effects
# from the yellow paper
InstructionIL = {
#    'ADD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.add(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'ADDMOD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.mod_unsigned(ADDR_SZ,
#                                il.add(ADDR_SZ,
#                                       il.pop(ADDR_SZ),
#                                       il.pop(ADDR_SZ)),
#                                il.pop(ADDR_SZ)))
#    ],
#    'ALL_PUSH': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.const(ADDR_SZ, operand))
#    ],
#    'ALL_DUP' : lambda il, addr, operand, operand_size, pops, pushes: [
#        dup(il, operand_size)
#    ],
#    'AND': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.and_expr(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'DIV': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.div_unsigned(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'EQ': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.compare_equal(ADDR_SZ,
#                                          il.pop(ADDR_SZ),
#                                          il.pop(ADDR_SZ)))
#    ],
#    'JUMP': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.jump(il.pop(ADDR_SZ))
#    ],
#    'JUMPDEST': lambda il, addr, operand, operand_size, pops, pushes: [
#        label(il, addr)
#    ],
#    'JUMPI': lambda il, addr, operand, operand_size, pops, pushes: [
#        cond_branch(il, operand)
#    ],
#    'GAS': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.reg(8, 'gas'))
#    ],
#    'GT': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.compare_unsigned_greater_than(ADDR_SZ,
#                                                          il.pop(ADDR_SZ),
#                                                          il.pop(ADDR_SZ)))
#    ],
    'INVALID': lambda il, addr, operand, operand_size, pops, pushes: il.no_ret(),
#    'ISZERO': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.not_expr(ADDR_SZ, il.pop(ADDR_SZ)))
#    ],
    'RETURN': lambda il, addr, operand, operand_size, pops, pushes: [
        il.ret(il.pop(ADDR_SZ))
    ],
    'REVERT': lambda il, addr, operand, operand_size, pops, pushes: il.no_ret(),
#    'SDIV': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.div_signed(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'SIGNEXTEND': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.sign_extedn(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ))),
#    ],
#    'SLT': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.compare_signed_less_than(ADDR_SZ,
#                                                     il.pop(ADDR_SZ),
#                                                     il.pop(ADDR_SZ)))
#    ],
#    'SLT': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.compare_signed_greater_than(ADDR_SZ,
#                                                        il.pop(ADDR_SZ),
#                                                        il.pop(ADDR_SZ)))
#    ],
#    'SMOD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.mod_signed(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'STOP': lambda il, addr, operand, operand_size, pops, pushes: il.no_ret(),
#    'ALL_SWAP': lambda il, addr, operand, operand_size, pops, pushes: [
#        swap(il, 1, operand_size + 1),
#    ],
#    'SUB': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.sub(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ))),
#    ],
    'SUICIDE': lambda il, addr, operand, operand_size, pops, pushes: [
        il.ret(il.pop(ADDR_SZ))
    ],
#    'LT': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.compare_unsigned_less_than(ADDR_SZ,
#                                                       il.pop(ADDR_SZ),
#                                                       il.pop(ADDR_SZ)))
#    ],
#    'MLOAD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.load(ADDR_SZ, il.pop(ADDR_SZ)))
#    ],
#    'MOD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.mod_unsigned(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    # FIXME wrong!
#    'MSTORE': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.store(ADDR_SZ, il.load(ADDR_SZ, il.pop(ADDR_SZ)), il.pop(ADDR_SZ))
#    ],
#    'MUL': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.mult(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'MULMOD': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ,
#                il.mod_unsigned(ADDR_SZ,
#                                il.mult(ADDR_SZ,
#                                        il.pop(ADDR_SZ),
#                                        il.pop(ADDR_SZ)),
#                                il.pop(ADDR_SZ)))
#    ],
#    'NOT': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.not_expr(ADDR_SZ, il.pop(ADDR_SZ)))
#    ],
#    'OR': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.or_expr(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
#    'POP': lambda il, addr, operand, operand_size, pops, pushes: il.pop(ADDR_SZ),
#    'XOR': lambda il, addr, operand, operand_size, pops, pushes: [
#        il.push(ADDR_SZ, il.xor_expr(ADDR_SZ, il.pop(ADDR_SZ), il.pop(ADDR_SZ)))
#    ],
    'SELFDESTRUCT': lambda il, addr, operand, operand_size, pops, pushes: il.no_ret(),
}

class EVM(Architecture):
    name = 'evm'
    address_size = ADDR_SZ * 8
    default_int_size = ADDR_SZ * 8
    # FIXME
    max_instr_length = ADDR_SZ * 8 + 1
    endianness = Endianness.BigEndian
    regs = {'sp': RegisterInfo('sp', ADDR_SZ), 'gas' : RegisterInfo('gas', 8)}
    stack_pointer = 'sp'
    flags = []

    def decode_instruction(self, data, addr):
        instruction = EVMDecoder.decode_one(data)
        return instruction

    def perform_get_instruction_info(self, data, addr):
#        cache = getattr(self, 'cache', {})
 #       setattr(self, 'cache', cache)
        instruction = EVMDecoder.decode_one(data)

        if instruction is None:
            return instruction

        result = InstructionInfo()
        result.length = instruction.size

        # Add branches
        if instruction.name in ['RETURN']:
            result.add_branch(BranchType.FunctionReturn)
        elif instruction.name in ['REVERT', 'SUICIDE', 'INVALID', 'STOP']:
            result.add_branch(BranchType.UnresolvedBranch)
        elif instruction.name in ['JUMPI']:
            result.add_branch(BranchType.UnresolvedBranch)
        elif instruction.name in ['JUMP']:
            result.add_branch(BranchType.UnresolvedBranch)
            # TODO binja crash on some calls instruction, inspect this_
       # elif instruction.name in ['CALL', 'CALLCODE', 'DELEGATECALL']:
            #print BranchType.CallDestination
            #  result.add_branch(BranchType.CallDestination, None)
        return result

    def perform_get_instruction_text(self, data, addr):
        instruction = EVMDecoder.decode_one(data)
        if instruction is None:
            return instruction

        tokens = []


        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken,
                                 '{:7s}'.format(instruction.name))
        ]

        if instruction.has_operand:
            operand = instruction.operand
            tokens.append(InstructionTextToken((InstructionTextTokenType
                                                .IntegerToken),
                                               '{:#x}'.format(operand),
                                               operand))

        return tokens, instruction.size

    def _get_name(self, name):
        name = name.lstrip().rstrip()
        multiple_ops = ["PUSH", "DUP", "SWAP"]
        for op in multiple_ops:
            if name.startswith(op):
                if name != op:
                    return "ALL_" + op
        return name

    def perform_get_instruction_low_level_il(self, data, addr, il):
        insn = self.decode_instruction(data, addr)
        # opcode: (name, immediate_operand_size, pops, pushes, description)
        if insn is None:
            return None
        name = self._get_name(insn.name)
        # pay the gas upfront
        gas(il, name)
        # see what we execute
        if InstructionIL.get(name) is None:
            il.append(il.unimplemented())
        else:
            ilins = InstructionIL[name](il,
                                        addr,
                                        insn.operand,
                                        insn.operand_size,
                                        insn.pops,
                                        insn.pushes)
            if isinstance(ilins, list):
                for i in [i for i in ilins if i is not None]:
                    il.append(i)
            elif ilins is not None:
                il.append(ilins)
        return insn.size

    def perform_assemble(self, code, addr):
        return None

class EVMView(BinaryView):
    name = "EVM"
    long_name = "EVM"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        self.arch = Architecture['evm']
        self.platform = self.arch.standalone_platform

    def init(self):
        try:
            file_size = len(self.raw)
            self.entry_addr = 0
            self.add_entry_point(self.entry_addr)
            self.add_auto_segment(0, file_size, 0, file_size,
                                  (SegmentFlag.SegmentReadable |
                                   SegmentFlag.SegmentExecutable))
            t = threading.Thread(target=self.check_if_initialized)
            t.start()
            return True
        except Exception as e:
            log_error(traceback.print_stack())
            return False

    def _analyze(self):
        # create methods
        CreateMethods(self).explore(self.get_basic_blocks_at(0)[0])
        total_hashes = 0

        for f in self.functions:
            h = HashMatcher(f)
            if f.basic_blocks is not None:
                try:
                    h.explore(f.basic_blocks[0])
                except IndexError:
                    log_error("Failed to explore " + str(f))

        for f in self.functions:
            function_dynamic_jump_start(self, f)

    def check_if_initialized(self):
        while not self.get_basic_blocks_at(0):
            time.sleep(2)
        start = self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,
                                               0,
                                               "_dispatcher"))
        self._analyze()
        log.log(1,  'Initialization done')

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr

    @classmethod
    def is_valid_for_data(self, data):
        return data.file.filename.endswith('.bytecode')



