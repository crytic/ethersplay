'''
    Stack value analysis based on a ligh value set analysis.
    We only represent the stack, and follow a best effort strategy.
'''

import itertools
import time

from binaryninja import HighlightStandardColor
from binaryninja.interaction import IntegerField, ChoiceField, get_form_input
from binaryninja.function import InstructionTextToken

import sys
# VSA is heavy in recursion 
sys.setrecursionlimit(15000)

class AbsStackElem(object):
    '''
        Represent an element of the stack
        An element is a set of potential values.
        There are at max MAXVALS number of values, otherwise it is set to TOP

        TOP is representented as None

        []     --> [1, 2, None, 3...]  --> None
        Init   --> [ up to 10 vals ]   --  TOP

        If a value is not known, it is None.
        Note that we make the difference between the list beeing TOP, and one of the value inside
        the list beeing TOP. The idea is that even if one of the value is not known,
        we can list keep track of the known values.

        Thus our analysis is an under-approximation of an over-approximation and is not sound.
    '''

    MAXVALS = 10 # Maximum number of values inside the set. If > MAXVALS -> TOP

    def __init__(self):
        self._vals = []

    def append(self, nbr):
        '''
            Append value to the element

        Args:
            nbr (int or long or binaryninja.function.InstructionTextToken or None)
        '''
        if not nbr:
            self._vals.append(None)
        elif isinstance(nbr, (int, long)):
            self._vals.append(nbr)
        elif isinstance(nbr, InstructionTextToken):
            self._vals.append(long(str(nbr), 16))
        else:
            raise Exception('Wrong type in AbsStackElem.append %s %s'%(str(nbr), type(nbr)))

    def get_vals(self):
        '''
            Return the values. The return must be checked for TOP (None)

        Returns:
            list of int, or None
        '''
        return self._vals

    def set_vals(self, vals):
        '''
            Set the values
        Args:
            vals (list of int, or None): List of values, or TOP
        '''
        self._vals = vals

    def absAnd(self, elem):
        '''
            AND between two AbsStackElem
        Args:
            elem (AbsStackElem)
        Returns:
            AbsStackElem: New object containing the result of the AND between the values
                          If one of the absStackElem is TOP, returns TOP
        '''
        newElem = AbsStackElem()
        v1 = self.get_vals()
        v2 = elem.get_vals()
        if not v1 or not v2:
            newElem.set_vals(None)
            return newElem
        combi = list(itertools.product(v1, v2))
        for (a, b) in combi:
            if a is None:
                newElem.append(None)
            elif b is None:
                newElem.append(None)
            else:
                newElem.append(a & b)
        return newElem

    def merge(self, elem):
        '''
            Merge between two AbsStackElem
        Args:
            elem (AbsStackElem)
        Returns:
            AbsStackElem: New object containing the result of the merge
                          If one of the absStackElem is TOP, returns TOP
        '''
        newElem = AbsStackElem()
        v1 = self.get_vals()
        v2 = elem.get_vals()
        if not v1 or not v2:
            newElem.set_vals(None)
            return newElem
        vals = list(set(v1 + v2))
        if len(vals) > self.MAXVALS:
            vals = None
        newElem.set_vals(vals)
        return newElem

    def equals(self, elems):
        '''
            Return True if equal
        Args:
            elem (AbsStackElem)
        Returns:
            bool: True if the two absStackElem are equals. If both are TOP returns True
        '''
        v1 = self.get_vals()
        v2 = elems.get_vals()
        if not v1 or not v2:
            if not v1 and not v2:
                return True
            return False
        if len(v1) != len(v2):
            return False
        for v in v1:
            if not v in v2:
                return False
        return True

    def get_copy(self):
        '''
            Return of copy of the object
        Returns:
            AbsStackElem
        '''
        cp = AbsStackElem()
        cp.set_vals(self.get_vals())
        return cp

    def __str__(self):
        '''
            String representation
        Returns:
            str
        '''
        return str(self._vals)

class Stack(object):
    '''
        Stack representation
        The stack is updated throyugh the push/pop/dup operation, and returns itself
        We keep the same stack for one basic block, to reduce the memory usage
    '''

    def __init__(self):
        self._elems = []

    def copy_stack(self, stack):
        '''
            Copy the given stack

        Args:
            Stack: stack to copy
        '''
        self._elems = [x.get_copy() for x in stack.get_elems()]

    def push(self, elem):
        '''
            Push an elem. If the elem is not an AbsStackElem, create a new AbsStackElem
        Args:
            elem (AbsStackElem, or str or None): If str, it should be the hexadecimal repr
        '''
        if not isinstance(elem, AbsStackElem):
            st = AbsStackElem()
            st.append(elem)
            elem = st
        self._elems.append(elem)

    def pop(self):
        '''
            Pop an element.
        Returns:
            AbsStackElem
        '''
        if not self._elems:
            self.push(None)
        return self._elems.pop()

    def swap(self, n):
        '''
            Swap operation
        Args:
            n (int)
        '''
        if len(self._elems) >= (n+1):
            elem = self._elems[-1-n]
            top = self.top()
            self._elems[-1] = elem
            self._elems[-1-n] = top
        # if we swap more than the size of the stack,
        # we can assume that elemements are missing in the stack
        else:
            top = self.top()
            self.push(None)
            missing_elems = n - len(self._elems) + 1
            for _ in range(0, missing_elems):
                self.push(None)
            self._elems[-1-n] = top

    def dup(self, n):
        '''
            Dup operation
        '''
        if len(self._elems) >= n:
            self.push(self._elems[-n])
        else:
            self.push(None)

    def get_elems(self):
        '''
            Returns the stack elements
        Returns:
            List AbsStackElem
        '''
        return self._elems

    def set_elems(self, elems):
        '''
            Set the stack elements
        Args:
            elems (list of AbsStackElem)
        '''
        self._elems = elems

    def merge(self, stack):
        '''
            Merge two stack. Returns a new object
        Arg:
            stack (Stack)
        Returns: New object representing the merge
        '''
        newSt = Stack()
        elems1 = self.get_elems()
        elems2 = stack.get_elems()
        # We look for the longer stack
        if len(elems2) <= len(elems1):
            longStack = elems1
            shortStack = elems2
        else:
            longStack = elems2
            shortStack = elems1
        longStack = [x.get_copy() for x in longStack]
        # Merge elements
        for i in xrange(0, len(shortStack)):
            longStack[-(i+1)] = longStack[-(i+1)].merge(shortStack[-(i+1)])
        newSt.set_elems(longStack)
        return newSt

    def equals(self, stack):
        '''
            Test equality between two stack
        Args:
            stack (Stack)
        Returns:
            bool: True if the stac are equals
        '''
        elems1 = self.get_elems()
        elems2 = stack.get_elems()
        if len(elems1) != len(elems2):
            return False
        for (v1, v2) in zip(elems1, elems2):
            if not v1.equals(v2):
                return False
        return True

    def top(self):
        '''
            Return the element at the top (without pop)
        Returns:
            AbsStackElem
        '''
        if not self._elems:
            self.push(None)
        return self._elems[-1]

    def __str__(self):
        '''
            String representation (only first 5 items)
        '''
        return str([str(x) for x in self._elems[-5::]])

class StackValueAnalysis(object):
    '''
        Stack value analysis.
        After each convergence, we add the new branches, update the binja view and
        re-analyze the function. The exploration is bounded in case the analysis is lost.

    '''

    # TODO: this could come from EVMAsm
    # name: (number pop, number push)
    table = {
        'STOP': (0, 0),
        'ADD': (2, 1),
        'MUL': (2, 1),
        'SUB': (2, 1),
        'DIV': (2, 1),
        'SDIV': (2, 1),
        'MOD': (2, 1),
        'SMOD': (2, 1),
        'ADDMOD': (3, 1),
        'MULMOD': (3, 1),
        'EXP': (2, 1),
        'SIGNEXTEND': (2, 1),
        'LT': (2, 1),
        'GT': (2, 1),
        'SLT': (2, 1),
        'SGT': (2, 1),
        'EQ': (2, 1),
        'ISZERO': (1, 1),
        'AND': (2, 1),
        'OR': (2, 1),
        'XOR': (2, 1),
        'NOT': (1, 1),
        'BYTE': (2, 1),
        'SHA3': (2, 1),
        'ADDRESS': (0, 1),
        'BALANCE': (1, 1),
        'ORIGIN': (0, 1),
        'CALLER': (0, 1),
        'CALLVALUE': (0, 1),
        'CALLDATALOAD': (1, 1),
        'CALLDATASIZE': (0, 1),
        'CALLDATACOPY': (3, 0),
        'CODESIZE': (0, 1),
        'CODECOPY': (3, 0),
        'GASPRICE': (0, 1),
        'EXTCODESIZE': (1, 1),
        'EXTCODECOPY': (4, 0),
        'BLOCKHASH': (1, 1),
        'COINBASE': (0, 1),
        'TIMESTAMP': (0, 1),
        'NUMBER': (0, 1),
        'DIFFICULTY': (0, 1),
        'GASLIMIT': (0, 1),
        'POP': (1, 0),
        'MLOAD': (1, 1),
        'MSTORE': (2, 0),
        'MSTORE8': (2, 0),
        'SLOAD': (1, 1),
        'SSTORE': (2, 0),
        'JUMP': (1, 0),
        'JUMPI': (2, 0),
        'GETPC': (0, 1),
        'MSIZE': (0, 1),
        'GAS': (0, 1),
        'JUMPDEST': (0, 0),
        'PUSH1': (0, 1),
        'PUSH2': (0, 1),
        'PUSH3': (0, 1),
        'PUSH4': (0, 1),
        'PUSH5': (0, 1),
        'PUSH6': (0, 1),
        'PUSH7': (0, 1),
        'PUSH8': (0, 1),
        'PUSH9': (0, 1),
        'PUSH10': (0, 1),
        'PUSH11': (0, 1),
        'PUSH12': (0, 1),
        'PUSH13': (0, 1),
        'PUSH14': (0, 1),
        'PUSH15': (0, 1),
        'PUSH16': (0, 1),
        'PUSH17': (0, 1),
        'PUSH18': (0, 1),
        'PUSH19': (0, 1),
        'PUSH20': (0, 1),
        'PUSH21': (0, 1),
        'PUSH22': (0, 1),
        'PUSH23': (0, 1),
        'PUSH24': (0, 1),
        'PUSH25': (0, 1),
        'PUSH26': (0, 1),
        'PUSH27': (0, 1),
        'PUSH28': (0, 1),
        'PUSH29': (0, 1),
        'PUSH30': (0, 1),
        'PUSH31': (0, 1),
        'PUSH32': (0, 1),
        'DUP1': (1, 2),
        'DUP2': (2, 3),
        'DUP3': (3, 4),
        'DUP4': (4, 5),
        'DUP5': (5, 6),
        'DUP6': (6, 7),
        'DUP7': (7, 8),
        'DUP8': (8, 9),
        'DUP9': (9, 10),
        'DUP10': (10, 11),
        'DUP11': (11, 12),
        'DUP12': (12, 13),
        'DUP13': (13, 14),
        'DUP14': (14, 15),
        'DUP15': (15, 16),
        'DUP16': (16, 17),
        'SWAP1': (2, 2),
        'SWAP2': (3, 3),
        'SWAP3': (4, 4),
        'SWAP4': (5, 5),
        'SWAP5': (6, 6),
        'SWAP6': (7, 7),
        'SWAP7': (8, 8),
        'SWAP8': (9, 9),
        'SWAP9': (10, 10),
        'SWAP10': (11, 11),
        'SWAP11': (12, 12),
        'SWAP12': (13, 13),
        'SWAP13': (14, 14),
        'SWAP14': (15, 15),
        'SWAP15': (16, 16),
        'SWAP16': (17, 17),
        'LOG0': (2, 0),
        'LOG1': (3, 0),
        'LOG2': (4, 0),
        'LOG3': (5, 0),
        'LOG4': (6, 0),
        'CREATE': (3, 1),
        'CALL': (7, 1),
        'CALLCODE': (7, 1),
        'RETURN': (2, 0),
        'DELEGATECALL': (6, 1),
        'BREAKPOINT': (0, 0),
        'RNGSEED': (1, 1),
        'SSIZEEXT': (2, 1),
        'SLOADBYTES': (3, 0),
        'SSTOREBYTES': (3, 0),
        'SSIZE': (1, 1),
        'STATEROOT': (1, 1),
        'TXEXECGAS': (0, 1),
        'REVERT': (2, 0),
        'INVALID': (0, 0),
        'SELFDESTRUCT': (1, 0)
    }



    def __init__(self, view, func, maxiteration=100, maxexploration=10, print_values=False, initStack=None):
        '''
        Args:
            view (binaryninja.binaryview.BinaryView)
            func (binaryninja.function.Function)
            maxiteration (int): number of time re-analyze the function
            maxexploration (int): number of time re-explore a bb
        '''
        # last targets discovered. We keep track of these branches to only re-launch
        # the analysis on new paths found
        self.last_discovered_targets = {}
        # all the targets discovered
        self.all_discovered_targets = {}
        self.func = func
        self.view = view
        self.stacksIn = {}
        self.stacksOut = {}
        self.bb_counter = {} # bb counter, to bound the bb exploration
        self.counter = 0 # number of time the function was analysis, to bound the analysis recursion
        # limit the number of time we re-analyze a function
        self.MAXITERATION = maxiteration
        # limit the number of time we explore a basic block (unrool)
        self.MAXEXPLORATION = maxexploration
        self.print_values = print_values
        self.initStack = initStack

    def is_jumpdst(self, addr):
        '''
            Check that an instruction is a JUMPDEST
            A JUMP to no-JUMPDEST instruction is not valid (see yellow paper).
            Yet some assembly tricks use a JUMP to an invalid instruction to
            trigger THROW. We need to filter those jumps
        Args:
            addr (int)
        Returns:
            bool: True if the instruction is a JUMPDEST
        '''
        ins = self.view.get_disassembly(addr)
        return ins == 'JUMPDEST'

    def stub(self, ins, addr, stack):
        return (False, None)

    def _transfer_func_ins(self, ins, addr, stackIn):
        stack = Stack()
        stack.copy_stack(stackIn)

        (is_stub, stub_ret) = self.stub(ins, addr, stack)
        if is_stub:
            return stub_ret

        op = str(ins[0]).replace(' ', '')
        if op.startswith('PUSH'):
            stack.push(ins[1])
        elif op.startswith('SWAP'):
            nth_elem = int(op[4])
            stack.swap(nth_elem)
        elif op.startswith('DUP'):
            nth_elem = int(op[3])
            stack.dup(nth_elem)
        elif op == 'AND':
            v1 = stack.pop()
            v2 = stack.pop()
            stack.push(v1.absAnd(v2))
        # For all the other opcode: remove
        # the pop elements, and push None elements
        # if JUMP or JUMPI saves the last value before poping
        else:
            (n_pop, n_push) = self.table[op]
            for _ in xrange(0, n_pop):
                stack.pop()
            for _ in xrange(0, n_push):
                stack.push(None)

        return stack

    def _explore_bb(self, bb, stack):
        '''
            Update the stack of a basic block. Return the last jump/jumpi target

            The last jump value is returned, as the JUMP/JUMPI instruction will
            pop the value before returning the function

            self.stacksOut will contain the stack of last instruction of the basic block.
        Args:
            bb
            stack (Stack)
        Returns:
            AbsStackElem: last jump computed.
        '''
        last_jump = None
        addr = bb.start
        size = 0

        for (ins, size) in bb.__iter__():
            if self.print_values:
                self.func.set_comment(addr, "STACK " + str(stack))

            self.stacksIn[addr] = stack
            stack = self._transfer_func_ins(ins, addr, stack)

            self.stacksOut[addr] = stack
            addr += size

        if ins:
            # if we are going to do a jump / jumpi
            # get the destination
            op = str(ins[0]).replace(' ', '')
            if op == 'JUMP' or op == 'JUMPI':
                last_jump = stack.top()
        return last_jump

    def end_bb(self, bb):
        addr = bb.start
        size = 0
        ins = None
        for (ins, size) in bb.__iter__():
            addr += size
        addr -= size
        return (addr, ins)

    def _transfer_func_bb(self, bb, init=False):
        '''
            Transfer function
        '''
        addr = bb.start
        (end, end_ins) = self.end_bb(bb)

        # bound the number of times we analyze a BB
        if not addr in self.bb_counter:
            self.bb_counter[addr] = 1
        else:
            self.bb_counter[addr] += 1
            if self.bb_counter[addr] > self.MAXEXPLORATION:
                return

        # Check if the bb was already analyzed (used for convergence)
        if (end) in self.stacksOut:
            prev_stack = self.stacksOut[end]
        else:
            prev_stack = None

        # Merge all the stack fathers
        # We merge only father that were already analyzed
        fathers = bb.incoming_edges
        fathers = [x.source  for x in fathers]
        if init and self.initStack:
            stack = self.initStack
        else:
            stack = Stack()
        if len(fathers) > 1 and not init:
            i = 0
            d_start = None
            for i in xrange(0, len(fathers)):
                if (fathers[i].end -1) in self.stacksOut:
                    d_start = fathers[i]
            if not d_start:
                return
            if (d_start.end -1) in self.stacksOut:
                stack.copy_stack(self.stacksOut[d_start.end -1])
                fathers = fathers[:i] + fathers[i+1:]
                for d in fathers:
                    if (d.end -1) in self.stacksOut:
                        stack2 = self.stacksOut[d.end -1]
                        stack = stack.merge(stack2)
        elif len(fathers) == 1 and not init:
            father = fathers[0]
            if (father.end - 1) in self.stacksOut:
                stack.copy_stack(self.stacksOut[father.end - 1])
            else:
                return

        # Analyze the BB
        self._explore_bb(bb, stack)

        # check if the last instruction is a JUMP
        op = str(end_ins[0]).replace(' ', '')
        if op == 'JUMP':
            src = end
            dst = self.stacksIn[end].top().get_vals()
            if dst:
                dst = [x for x in dst if x and self.is_jumpdst(x)]
                self.add_branches(src, dst)
        elif op == 'JUMPI':
            src = end
            dst = self.stacksIn[end].top().get_vals()
            if dst:
                dst = [x for x in dst if x and self.is_jumpdst(x)]
                self.add_branches(src, dst)

        # check for convergence
        converged = False
        if prev_stack:
            if prev_stack.equals(self.stacksOut[end]):
                converged = True
        if not converged:
            for son in bb.outgoing_edges:
                son = son.target
                self._transfer_func_bb(son)

    def add_branches(self, src, dst):
        '''
            Add new branches
        Ags:
            src (int)
            dst (list of int)
        '''
        if src not in self.all_discovered_targets:
            self.all_discovered_targets[src] = set()

        for d in dst:
            if not d in self.all_discovered_targets[src]:
                if src not in self.last_discovered_targets:
                    self.last_discovered_targets[src] = set()
                self.last_discovered_targets[src].add(d)
                self.all_discovered_targets[src].add(d)

    def _update_func(self):
        '''
            Update the function with new branches
        '''
        for (src, dst) in self.all_discovered_targets.iteritems():
            branches = [(self.func.arch, x) for x in dst]
            self.func.set_user_indirect_branches(src, branches)
        self.view.update_analysis_and_wait()

    def explore_new(self):
        '''
            Re-launch the analysis on new targets found
        '''
        self.counter = self.counter + 1
        # Bound the recursion
        if self.counter >= self.MAXITERATION:
            return
        if not self.last_discovered_targets:
            return
        self._update_func()

        # only explore new targets discovered
        to_explore = []
        for (_, dsts) in self.last_discovered_targets.iteritems():
            to_explore += dsts
        self.last_discovered_targets = {}
        for dst in set(to_explore):
            self.bb_counter = {}
            bb = self.func.get_basic_block_at(dst)
            if bb:
                self._transfer_func_bb(bb)
        self.explore_new()

    def explore(self):
        """
            Launch the analysis
        """
        self.bb_counter = {}
        self._transfer_func_bb(self.func.get_basic_block_at(self.func.start), True)
        self.explore_new()

        # Binja does not allow to save any type; None is not accepted
        # For each stack, the first element is a boolean
        # If true, the following value are correct
        # If false, it means that it was a None
        def filter_vals(vals):
            if None in vals:
                return [False, 0]
            return [True] + [float(x) for x in vals]

        stacksOut = {}
        for (k,v) in self.stacksOut.iteritems():
            elems = v.get_elems()
            elems = [filter_vals(x.get_vals()) for x in elems]
            stacksOut[k] = elems
        
        # The stack value are saved at key func_name.out
        self.view.store_metadata(self.func.name+".out", stacksOut)
        self.view.modified = True



def function_dynamic_jump_start(view, func):
    if func.arch.name != 'evm':
        print "This plugin works only for EVM bytecode"
        return
    print "JMP recovery on "+func.name
    sv = StackValueAnalysis(view, func, 100, 10)
    sv.explore()


