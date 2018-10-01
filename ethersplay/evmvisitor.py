from bisect import bisect_left
from binaryninja import log_debug

class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = 'visit_{}'.format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            value = None
        return value


class EVMVisitor(BNILVisitor):
    def __init__(self, **kw):
        super(EVMVisitor, self).__init__()
        self.function = None
        self.il_function = None
        self.bb = None
        self.il_bb_lookup = kw['lookup']

    def visit_MLIL_IF(self, expression):
        self.il_function = expression.function
        self.function = self.il_function.source_function
        self.bb = self.il_bb_lookup[expression.instr_index]

        condition = expression.condition.ssa_form

        return self.visit(condition)

    def visit_MLIL_VAR_SSA(self, expression):
        expr_def = self.il_function.get_ssa_var_definition(expression.src)

        if expr_def is None:
            return

        if self.il_bb_lookup[expr_def] != self.bb:
            return

        return self.visit(self.il_function[expr_def].ssa_form)

    def visit_MLIL_SET_VAR_ALIASED(self, expression):
        return self.visit(expression.src)

    def visit_MLIL_SET_VAR_SSA(self, expression):
        return self.visit(expression.src)

    def visit_MLIL_VAR_ALIASED(self, expression):
        expr_def = self.il_function.get_ssa_var_definition(expression.src)

        if expr_def is not None:
            return self.visit(self.il_function[expr_def].ssa_form)

        expr_defs = self.il_function.get_var_definitions(expression.src.var)

        expr_defs = expr_defs[
            bisect_left(
                expr_defs, self.bb.start
            ):bisect_left(
                expr_defs, expression.non_ssa_form.instr_index
            )
        ]

        for idx in reversed(expr_defs):
            current_bb = self.il_bb_lookup[idx]

            if current_bb == self.bb:
                return self.visit(self.il_function[idx].ssa_form)

    def visit_MLIL_CONST(self, expression):
        return expression.constant, expression

    def visit_MLIL_CONST_PTR(self, expression):
        return expression.constant, expression

    def visit_MLIL_CMP_E(self, expression):
        left = expression.left
        right = expression.right

        value = self.visit(left)

        if value is None:
            value = self.visit(right)

        return value
