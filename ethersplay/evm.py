#!/usr/bin/env python
# -*- coding: utf-8 -*-

from binaryninja import (LLIL_TEMP, Architecture, BinaryView, BranchType,
                         Endianness, InstructionInfo, InstructionTextToken,
                         InstructionTextTokenType, IntegerDisplayType,
                         LowLevelILLabel, MediumLevelILOperation, RegisterInfo,
                         SegmentFlag, SSAVariable, Symbol, SymbolType)
from evmasm import EVMAsm
from evmvisitor import EVMVisitor
from known_hashes import knownHashes


def jumpi(il, addr, imm):
    t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['EVM'], addr+1)
    must_mark = False

    if f is None:
        f = LowLevelILLabel()
        must_mark = True

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop(32)
    # first, but dest needs to be first.
    dest = il.pop(8)
    il.append(il.set_reg(8, LLIL_TEMP(addr), dest))

    il.append(il.set_reg(8, LLIL_TEMP(0), il.pop(8)))
    il.append(il.if_expr(il.reg(8, LLIL_TEMP(0)), t, f))

    il.mark_label(t)
    il.append(il.jump(il.reg(8, LLIL_TEMP(addr))))

    if must_mark:
        il.mark_label(f)
        # false is the fall through case
        il.append(il.jump(il.const(8, addr + 1)))

    return []


def dup(il, addr, distance):
    il.append(
        il.set_reg(
            8, LLIL_TEMP(0), il.load(
                8, il.add(
                    8, il.reg(8, 'sp'), il.const(8, (distance - 1) * 8)
                )
            )
        )
    )

    il.append(il.push(8, il.reg(8, LLIL_TEMP(0))))

    return []


def swap(il, addr, distance):
    stack_offset = distance * 8

    load = il.load(
        8, il.add(
            8, il.reg(8, 'sp'), il.const(8, stack_offset)
        )
    )

    il.append(il.set_reg(8, LLIL_TEMP(0), load))

    il.append(il.set_reg(8, LLIL_TEMP(1), il.load(8, il.reg(8, 'sp'))))

    il.append(
        il.store(
            8, il.add(
                8, il.reg(8, 'sp'), il.const(8, stack_offset)
            ),
            il.reg(8, LLIL_TEMP(1))
        )
    )
    il.append(il.store(8, il.reg(8, 'sp'), il.reg(8, LLIL_TEMP(0))))

    return []


def jump(il, addr, imm):
    dest = il.pop(8)
    il.append(il.set_reg(8, LLIL_TEMP(addr), dest))

    il.append(il.jump(il.reg(8, LLIL_TEMP(addr))))

    return []


def push(il, addr, imm):
    return il.push(8, il.const(8, imm & 0xffffffffffffffff))


def mstore(il, addr, imm):
    il.append(il.set_reg(8, LLIL_TEMP(0), il.pop(8)))
    il.append(il.set_reg(8, LLIL_TEMP(1), il.pop(8)))
    # il.append(
    #     il.store(8, il.unimplemented(), il.reg(8, LLIL_TEMP(1)))
    # )
    return []


insn_il = {
        'AND': lambda il, addr, imm: il.push(
            8, il.and_expr(8, il.pop(8), il.pop(8))
        ),
        'EQ': lambda il, addr, imm: il.push(
            8, il.compare_equal(8, il.pop(8), il.pop(8))
        ),
        'LT': lambda il, addr, imm: il.push(
            8, il.compare_unsigned_less_than(8, il.pop(8), il.pop(8))
        ),
        'POP': lambda il, addr, imm: il.pop(8),
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
        'RETURN': lambda il, addr, imm: il.ret(il.pop(8)),
        'INVALID': lambda il, addr, imm: il.no_ret(),
        'SUICIDE': lambda il, addr, imm: il.ret(il.pop(8)),
        'SELFDESTRUCT': lambda il, addr, imm: il.ret(il.pop(8)),
}


class EVM(Architecture):
    name = "EVM"

    # Actual size is 32 but we're going to truncate everything
    address_size = 8

    # should be 32
    default_int_size = 8

    instr_alignment = 1

    max_instr_length = 33

    endianness = Endianness.BigEndian

    regs = {
        "sp": RegisterInfo("sp", 8),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):
        instruction = EVMAsm.disassemble_one(data, addr)

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
        instruction = EVMAsm.disassemble_one(data, addr)

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
        instruction = EVMAsm.disassemble_one(data, addr)

        ill = insn_il.get(instruction.name, None)
        if ill is None:

            for i in xrange(instruction.pops):
                il.append(il.set_reg(8, LLIL_TEMP(i), il.pop(8)))

            for i in xrange(instruction.pushes):
                il.append(il.push(8, il.unimplemented()))

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
            return EVMAsm.assemble(code, addr), ''
        except Exception as e:
            return None, e.message


class EVMView(BinaryView):
    name = "EVM"
    long_name = "Ethereum Bytecode"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def init(self):
        self.arch = Architecture['EVM']
        self.platform = Architecture['EVM'].standalone_platform
        self.add_entry_point(0)

        file_size = len(self.raw)
        self.add_auto_segment(
            0, file_size-3, 3, file_size,
            (SegmentFlag.SegmentReadable |
                SegmentFlag.SegmentExecutable)
        )

        self.add_analysis_completion_event(analyze)
        return True

    @staticmethod
    def is_valid_for_data(data):
        file_header = data.read(0, 3)
        if file_header == 'EVM':
            return True
        return False

    def is_executable(self):
        return True

    def get_entry_point(self):
        return 0


def build_bb_lookup_table(mlil_function):
    lookup_table = [None] * len(mlil_function)
    for bb in mlil_function:
        for i in xrange(bb.start, bb.end):
            lookup_table[i] = bb
    return lookup_table


def get_stack_def_for_offset(il, stack_offset):
    dispatcher = il.function.non_ssa_form

    stack_var = il.get_var_for_stack_location(
        stack_offset
    )

    stack_var_version = il.get_ssa_var_version(
        stack_var
    )

    ssa_stack_var = SSAVariable(stack_var, stack_var_version)

    hash_def = dispatcher.get_ssa_var_definition(
        ssa_stack_var
    )

    hash_il = dispatcher[hash_def] if hash_def is not None else None

    if (hash_il is None or hash_il.src.operation not in
            (MediumLevelILOperation.MLIL_CONST,
             MediumLevelILOperation.MLIL_CONST_PTR)):
        return None

    return hash_il.src


def analyze(completion_event):
    view = completion_event.view

    view.define_auto_symbol(
        Symbol(
            SymbolType.FunctionSymbol,
            0,
            '_dispatcher'
        )
    )

    dispatch_functions = []

    dispatcher = view.get_function_at(0).medium_level_il

    il_bb_lookup = build_bb_lookup_table(dispatcher)

    # Iterate over all of the MLIL instructions and find all the JUMPI
    # instructions.
    current_bb = dispatcher.basic_blocks[0]
    while current_bb:
        il = current_bb[-1]
        if il.operation == MediumLevelILOperation.MLIL_IF:
            visitor = EVMVisitor(lookup=il_bb_lookup)
            visit_result = visitor.visit(il)

            if visit_result is None:
                current_bb = il_bb_lookup[il.false]
                continue

            value, hash_constant = visit_result

            # Locate the definition of the hash value so we can set
            # the int display type of the hash to a pointer. This
            # will let us display the hash name there as a different
            # color.
            stack_offset = dispatcher.source_function.get_reg_value_at(
                hash_constant.address, 'sp'
            ).offset

            hash_il = get_stack_def_for_offset(hash_constant, stack_offset)

            if hash_il is None:
                stack_offset += 8
                hash_il = get_stack_def_for_offset(hash_constant, stack_offset)

            hash_value = '#{:08x}'.format(value)

            # XXX: knownHashes uses a string of the hex as a key, it
            # is probably faster to use an int
            hash_hex = hex(value).replace('L', '')

            # Find the method name if it's known. Otherwise, just use
            # the hash.
            if hash_hex in knownHashes:
                method_name = knownHashes[hash_hex]
            else:
                method_name = hash_value

            # We use SymbolType.ImportedFunctionSymbol because it will
            # change the font color to orange. Gives it a little "pop"!
            #
            # ...yeah that's some stack humor for you.
            view.define_user_symbol(
                Symbol(
                    SymbolType.ImportedFunctionSymbol,
                    value,
                    '{} -> {}'.format(
                        hash_value, method_name
                    )
                )
            )

            if hash_il is not None:
                # Change the hash operand to display the Symbol.
                dispatcher.source_function.set_int_display_type(
                    hash_il.address,
                    hash_constant.constant,
                    0,
                    IntegerDisplayType.PointerDisplayType
                )

            # The dispatched function is down the True branch.
            target = dispatcher[il.true]

            # Make a function at the instruction following the
            # JUMPTARGET instruction. This makes the control flow graph
            # "fall through" to the function, pruning those basic blocks
            # from the dispatcher function.
            if target.operation == MediumLevelILOperation.MLIL_JUMP_TO:
                dispatch_functions.append(
                    (target.dest.constant + 1, method_name)
                )

            current_bb = il_bb_lookup[il.false]

        else:
            current_bb = None

    # Go over all the functions we noted above and actually create the function
    # there. We do this last to make sure that view.mlil_instructions doesn't
    # get messed with while we're iterating over it.
    for addr, method_name in dispatch_functions:
        view.create_user_function(addr)
        dispatch_function = view.get_function_at(addr)
        dispatch_function.name = method_name
