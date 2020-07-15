#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from builtins import range
except ImportError:
    pass

from interval3 import Interval, IntervalSet

from binaryninja import (LLIL_TEMP, Architecture, BinaryDataNotification,
                         BinaryView, BranchType, Endianness, InstructionInfo,
                         InstructionTextToken, InstructionTextTokenType, Function,
                         LowLevelILLabel, LowLevelILOperation, RegisterInfo, log_info,
                         SegmentFlag, Symbol, SymbolType, log_debug, Settings, SettingsScope)
from binaryninja.function import _FunctionAssociatedDataStore
from pyevmasm import assemble, disassemble_one

from .analysis import VsaNotification
from .common import ADDR_SIZE
from evm_cfg_builder.cfg import CFG


def jumpi(il, addr, imm):
    dest = il.pop(ADDR_SIZE)

    if len(il) > 0:
        push = il[len(il)-1]
    else:
        push = None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    else:
        il.append(dest)

    t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['EVM'], addr+1)
    must_mark = False

    if f is None:
        f = LowLevelILLabel()
        must_mark = True

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    #il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.if_expr(il.reg(ADDR_SIZE, LLIL_TEMP(0)), t, f))

    il.mark_label(t)
    il.append(il.jump(il.unimplemented()))  # il.reg(ADDR_SIZE, LLIL_TEMP(1))))

    if must_mark:
        il.mark_label(f)
        # false is the fall through case
        il.append(il.jump(il.const(ADDR_SIZE, addr + 1)))

    return []


def dup(il, addr, distance):
    il.append(
        il.set_reg(
            ADDR_SIZE, LLIL_TEMP(0), il.load(
                ADDR_SIZE, il.add(
                    ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
                    il.const(ADDR_SIZE, (distance - 1) * ADDR_SIZE)
                )
            )
        )
    )

    il.append(il.push(ADDR_SIZE, il.reg(ADDR_SIZE, LLIL_TEMP(0))))

    return []


def swap(il, addr, distance):
    stack_offset = distance * ADDR_SIZE

    load = il.load(
        ADDR_SIZE, il.add(
            ADDR_SIZE,
            il.reg(ADDR_SIZE, 'sp'),
            il.const(ADDR_SIZE, stack_offset)
        )
    )

    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), load))

    il.append(
        il.set_reg(
            ADDR_SIZE, LLIL_TEMP(1),
            il.load(ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'))
        )
    )

    il.append(
        il.store(
            ADDR_SIZE, il.add(
                ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
                il.const(ADDR_SIZE, stack_offset)
            ),
            il.reg(ADDR_SIZE, LLIL_TEMP(1))
        )
    )
    il.append(
        il.store(
            ADDR_SIZE, il.reg(ADDR_SIZE, 'sp'),
            il.reg(ADDR_SIZE, LLIL_TEMP(0))
        )
    )

    return []


def jump(il, addr, imm):
    dest = il.pop(ADDR_SIZE)

    if len(il) > 0:
        push = il[len(il)-1]
    else:
        push = None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.jump(il.reg(ADDR_SIZE, LLIL_TEMP(addr))))

    return []


def push(il, addr, imm):
    return il.push(ADDR_SIZE, il.const(ADDR_SIZE, imm))


def mstore(il, addr, imm):
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), il.pop(ADDR_SIZE)))
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(1), il.pop(ADDR_SIZE)))
    # il.append(
    #     il.store(
    #         ADDR_SIZE,
    #         il.unimplemented(),
    #         il.reg(ADDR_SIZE, LLIL_TEMP(1))
    #     )
    # )
    return []


insn_il = {
    'AND': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.and_expr(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'EQ': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.compare_equal(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'LT': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.compare_unsigned_less_than(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE)
        )
    ),
    'ISZERO': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.compare_equal(
            ADDR_SIZE, il.pop(ADDR_SIZE), il.const(ADDR_SIZE, 0)
        )
    ),
    'POP': lambda il, addr, imm: il.pop(ADDR_SIZE),
    'MSTORE': mstore,
    'JUMP': jump,
    'JUMPI': jumpi,
    'PUSH1':  push,
    'PUSH2':  push,
    'PUSH3':  push,
    'PUSH4':  push,
    'PUSH5':  push,
    'PUSH6':  push,
    'PUSH7':  push,
    'PUSH8':  push,
    'PUSH9':  push,
    'PUSH10': push,
    'PUSH11': push,
    'PUSH12': push,
    'PUSH13': push,
    'PUSH14': push,
    'PUSH15': push,
    'PUSH16': push,
    'PUSH17': push,
    'PUSH18': push,
    'PUSH19': push,
    'PUSH20': push,
    'PUSH21': push,
    'PUSH22': push,
    'PUSH23': push,
    'PUSH24': push,
    'PUSH25': push,
    'PUSH26': push,
    'PUSH27': push,
    'PUSH28': push,
    'PUSH29': push,
    'PUSH30': push,
    'PUSH31': push,
    'PUSH32': push,
    'DUP1': lambda il, addr, imm: dup(il, addr, 1),
    'DUP2': lambda il, addr, imm: dup(il, addr, 2),
    'DUP3': lambda il, addr, imm: dup(il, addr, 3),
    'DUP4': lambda il, addr, imm: dup(il, addr, 4),
    'DUP5': lambda il, addr, imm: dup(il, addr, 5),
    'DUP6': lambda il, addr, imm: dup(il, addr, 6),
    'DUP7': lambda il, addr, imm: dup(il, addr, 7),
    'DUP8': lambda il, addr, imm: dup(il, addr, 8),
    'DUP9': lambda il, addr, imm: dup(il, addr, 9),
    'DUP10': lambda il, addr, imm: dup(il, addr, 10),
    'DUP11': lambda il, addr, imm: dup(il, addr, 11),
    'DUP12': lambda il, addr, imm: dup(il, addr, 12),
    'DUP13': lambda il, addr, imm: dup(il, addr, 13),
    'DUP14': lambda il, addr, imm: dup(il, addr, 14),
    'DUP15': lambda il, addr, imm: dup(il, addr, 15),
    'DUP16': lambda il, addr, imm: dup(il, addr, 16),
    'SWAP1': lambda il, addr, imm: swap(il, addr, 1),
    'SWAP2': lambda il, addr, imm: swap(il, addr, 2),
    'SWAP3': lambda il, addr, imm: swap(il, addr, 3),
    'SWAP4': lambda il, addr, imm: swap(il, addr, 4),
    'SWAP5': lambda il, addr, imm: swap(il, addr, 5),
    'SWAP6': lambda il, addr, imm: swap(il, addr, 6),
    'SWAP7': lambda il, addr, imm: swap(il, addr, 7),
    'SWAP8': lambda il, addr, imm: swap(il, addr, 8),
    'SWAP9': lambda il, addr, imm: swap(il, addr, 9),
    'SWAP10': lambda il, addr, imm: swap(il, addr, 10),
    'SWAP11': lambda il, addr, imm: swap(il, addr, 11),
    'SWAP12': lambda il, addr, imm: swap(il, addr, 12),
    'SWAP13': lambda il, addr, imm: swap(il, addr, 13),
    'SWAP14': lambda il, addr, imm: swap(il, addr, 14),
    'SWAP15': lambda il, addr, imm: swap(il, addr, 15),
    'SWAP16': lambda il, addr, imm: swap(il, addr, 16),
    'STOP': lambda il, addr, imm: il.no_ret(),
    'REVERT': lambda il, addr, imm: il.no_ret(),
    'RETURN': lambda il, addr, imm: il.ret(il.pop(ADDR_SIZE)),
    'INVALID': lambda il, addr, imm: il.no_ret(),
    'SUICIDE': lambda il, addr, imm: il.ret(il.pop(ADDR_SIZE)),
    'SELFDESTRUCT': lambda il, addr, imm: il.ret(il.pop(ADDR_SIZE)),
}


class EVM(Architecture):
    name = "EVM"

    # Actual size is 32 but we're going to truncate everything
    address_size = ADDR_SIZE

    # should be 32
    default_int_size = ADDR_SIZE

    instr_alignment = 1

    max_instr_length = 33

    endianness = Endianness.BigEndian

    regs = {
        "sp": RegisterInfo("sp", ADDR_SIZE),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):
        instruction = disassemble_one(data, addr)

        result = InstructionInfo()
        result.length = instruction.size
        if instruction.name == "JUMP":
            result.add_branch(BranchType.UnresolvedBranch)
        elif instruction.name == "JUMPI":
            result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + 1)
        elif instruction.name in ('RETURN', 'REVERT', 'SUICIDE', 'INVALID',
                                  'STOP', 'SELFDESTRUCT'):
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_text(self, data, addr):
        instruction = disassemble_one(data, addr)

        tokens = []
        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                "{:7} ".format(
                    instruction.name
                )
            )
        )

        if instruction.name.startswith('PUSH'):
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    '#{:0{i.operand_size}x}'.format(
                        instruction.operand, i=instruction
                    ),
                    instruction.operand
                )
            )

        return tokens, instruction.size

    def get_instruction_low_level_il(self, data, addr, il):
        instruction = disassemble_one(data, addr)

        ill = insn_il.get(instruction.name, None)
        if ill is None:

            for i in range(instruction.pops):
                il.append(
                    il.set_reg(ADDR_SIZE, LLIL_TEMP(i), il.pop(ADDR_SIZE))
                )

            for i in range(instruction.pushes):
                il.append(il.push(ADDR_SIZE, il.unimplemented()))

            il.append(il.nop())

            return instruction.size

        ils = ill(il, addr, instruction.operand)
        if isinstance(ils, list):
            for i in ils:
                il.append(il)
        else:
            il.append(ils)

        return instruction.size

    def assemble(self, code, addr=0):
        try:
            return assemble(code, addr), ''
        except Exception as e:
            return None, str(e)


class EVMView(BinaryView):
    name = "EVM"
    long_name = "Ethereum Bytecode"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def find_swarm_hashes(self, data):
        rv = []
        offset = data.find(b'\xa1ebzzr0')
        while offset != -1:
            log_debug("Adding r-- segment at: {:#x}".format(offset))
            rv.append((offset, 43))
            offset = data[offset+1:].find(b'\xa1ebzzr0')

        return rv

    def init(self):
        self.arch = Architecture['EVM']
        self.platform = Architecture['EVM'].standalone_platform
        self.max_function_size_for_analysis = 0

        file_size = len(self.raw)

        # Find swarm hashes and make them data
        evm_bytes = self.raw.read(0, file_size)

        # code is everything that isn't a swarm hash
        code = IntervalSet([Interval(0, file_size)])

        swarm_hashes = self.find_swarm_hashes(evm_bytes)
        for start, sz in swarm_hashes:
            self.add_auto_segment(
                start, sz,
                start, sz,
                (
                    SegmentFlag.SegmentContainsData |
                    SegmentFlag.SegmentDenyExecute |
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentDenyWrite
                )
            )

            code -= IntervalSet([Interval(start, start + sz)])

        for interval in code:
            if isinstance(interval, int):
                continue
            self.add_auto_segment(
                interval.lower_bound, interval.upper_bound,
                interval.lower_bound, interval.upper_bound,
                (
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable
                )
            )

        cfg = CFG(evm_bytes)
        Function.set_default_session_data('cfg', cfg)

        self.register_notification(VsaNotification())

        self.add_entry_point(0)

        for function in cfg.functions:
            function_start = (function._start_addr + 1
                              if function._start_addr != 0 else 0)

            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    function_start,
                    function.name
                )
            )

            self.add_function(function_start)

        # disable linear sweep
        Settings().set_bool(
            'analysis.linearSweep.autorun',
            False,
            view=self,
            scope=SettingsScope.SettingsResourceScope
        )

        return True

    @staticmethod
    def is_valid_for_data(data):
        return data.file.original_filename.endswith('.evm')

    def is_executable(self):
        return True

    def get_entry_point(self):
        return 0
