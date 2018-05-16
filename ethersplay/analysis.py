from binaryninja import (BinaryDataNotification, BranchType,
                         IntegerDisplayType, MediumLevelILOperation,
                         SegmentFlag, SSAVariable, Symbol, SymbolType)

from .common import EVM_HEADER
from .evmvisitor import EVMVisitor
from .known_hashes import knownHashes
from .stack_value_analysis import function_dynamic_jump_start


def analyze_invalid_jumps(view, dispatcher):
    invalid_jumps = []

    # walk the binary and find invalid jumps
    for bb in dispatcher.basic_blocks:
        for edge in bb.outgoing_edges:
            if edge.type == BranchType.IndirectBranch:

                # Does the jump not jump to a jumpdest?
                if (view.get_disassembly(edge.target.start) not in
                        ('JUMPDEST', 'INVALID')):
                    invalid_jumps.append((bb, edge))

                # Does the jump jump to an immediate pushed on the stack?
                elif (dispatcher.get_basic_block_at(edge.target.start).start !=
                      edge.target.start):
                    invalid_jumps.append((bb, edge))

    if not invalid_jumps:
        return

    # TODO: do this once and set it as BinaryView metadata so we don't
    # append a bunch of 0xfe bytes to the end of the file.
    invalid_block, error = view.arch.assemble('INVALID')
    if invalid_block is None:
        return

    invalid_address = len(view.parent_view) - len(EVM_HEADER)

    view.parent_view.write(len(view.parent_view), invalid_block)
    view.add_auto_segment(
        0, len(view.parent_view) - len(EVM_HEADER),
        len(EVM_HEADER), len(view.parent_view),
        SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    )

    for bb, edge in invalid_jumps:
        asm = bb.disassembly_text[-2]

        opcode = asm.tokens[0].text.strip()

        if (opcode.startswith('PUSH')):
            imm = invalid_address
            patch, error = view.arch.assemble('{} {}'.format(opcode, imm))

            if patch is not None:
                view.write(asm.address, patch)


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


def analyze_jumps(view, func):
    dispatch_functions = []

    # We'll reference these when determining if we need to create a function
    mlil_jumps = (
        MediumLevelILOperation.MLIL_JUMP_TO, MediumLevelILOperation.MLIL_JUMP
    )

    dispatcher = func.medium_level_il

    il_bb_lookup = build_bb_lookup_table(dispatcher)

    # Iterate over all of the MLIL instructions and find all the JUMPI
    # instructions.
    current_bb = dispatcher.basic_blocks[0]
    il = None
    while current_bb:
        if il is not None:
            current_bb = il_bb_lookup[il.false]

        il = current_bb[-1]

        if il.operation == MediumLevelILOperation.MLIL_IF:
            # add the fallback function
            if current_bb == dispatcher.basic_blocks[0]:
                true = dispatcher[il.true]
                if true.operation == MediumLevelILOperation.MLIL_JUMP_TO:
                    dispatch_functions.append(
                        (true.dest.constant+1, "_fallback")
                    )

            visitor = EVMVisitor(lookup=il_bb_lookup)
            visit_result = visitor.visit(il)

            if visit_result is None:
                continue

            value, hash_constant = visit_result

            if value < len(view):
                continue

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

            # Skip this one if there's already a symbol for the hash.
            # This will keep us from updating the function with the
            # Function.set_int_display_type later on, which will stop
            # us from triggering our own callback repeatedly
            if view.get_symbol_at(value) is not None:
                continue

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
            # JUMPDEST instruction. This makes the control flow graph
            # "fall through" to the function, pruning those basic blocks
            # from the dispatcher function.
            if target.operation in mlil_jumps:
                dispatch_functions.append(
                    (target.dest.constant + 1, method_name)
                )

        else:
            current_bb = None

    # Go over all the functions we noted above and actually create the function
    # there. We do this last to make sure that view.mlil_instructions doesn't
    # get messed with while we're iterating over it.
    for addr, method_name in dispatch_functions:
        view.create_user_function(addr)
        dispatch_function = view.get_function_at(addr)
        dispatch_function.name = method_name


class InvalidJumpCallback(BinaryDataNotification):
    def function_updated(self, view, func):
        analyze_invalid_jumps(view, func)


class DispatcherCallback(BinaryDataNotification):
    def function_updated(self, view, func):
        # Only execute if this is the dispatcher.
        if func.start != 0:
            return

        analyze_jumps(view, func)


class DynamicJumpCallback(BinaryDataNotification):
    def function_updated(self, view, func):
        function_dynamic_jump_start(view, func)
