import functools

from binaryninja import (LLIL_TEMP, BinaryDataNotification, BranchType,
                         IntegerDisplayType, MediumLevelILOperation,
                         PluginCommand, RegisterValueType, SegmentFlag,
                         SSAVariable, Symbol, SymbolType, VariableSourceType,
                         log_debug, log_info, worker_enqueue)

from .common import EVM_HEADER
from .evmvisitor import EVMVisitor
from .known_hashes import knownHashes
from .stack_value_analysis import stack_value_analysis


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
            # Let's determine if this target is both a constant
            # and a valid jump destination. If it's not, we won't be
            # adding it to anything.
            branch_target = il.get_reg_value(LLIL_TEMP(1))
            create_dispatch = (
                branch_target is not None and
                branch_target.type == RegisterValueType.ConstantValue and
                branch_target.value + 1 < len(func.view) and
                view.get_disassembly(branch_target.value) == 'JUMPDEST'
            )

            # add the fallback function
            if current_bb == dispatcher.basic_blocks[0] and create_dispatch:
                dispatch_functions.append(
                    (branch_target.value + 1, "_fallback")
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

            if create_dispatch:
                dispatch_functions.append(
                    (branch_target.value + 1, method_name)
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


def analyze_stack_values_callback(completion_event):
    log_debug('analyze_stack_values_callback')
    view = completion_event.view
    function = view.get_function_at(0)

    # Queue up the dispatcher analysis first
    view.register_notification(DispatcherCallback())

    # Queue up the rest of the stack value analysis
    view.register_notification(DynamicJumpCallback())

    # Add the analysis function to the queue of worker
    # threads
    analysis_worker = functools.partial(
        stack_value_analysis, view, function
    )

    worker_enqueue(analysis_worker)


class DispatcherCallback(BinaryDataNotification):
    def function_updated(self, view, func):
        log_info("function_updated {:x}".format(func.start))
        # Only execute if this is the dispatcher.
        if func.start != 0:
            # Unregister this notification, because we won't need to do it 
            # automatically again.
            unregister_callback = functools.partial(
                view.unregister_notification, self
            )
            worker_enqueue(unregister_callback)
            return

        # analyze_jumps(view, func)
        analysis_callback = functools.partial(analyze_jumps, view, func)
        worker_enqueue(analysis_callback)


class DynamicJumpCallback(BinaryDataNotification):
    def function_update_requested(self, view, func):
        log_info("function_update_requested {:x}".format(func.start))
    def function_updated(self, view, func):
        log_debug("DynamicJumpCallback start {:x}".format(func.start))
        analysis_callback = functools.partial(
            stack_value_analysis, view, func
        )
        worker_enqueue(analysis_callback)
