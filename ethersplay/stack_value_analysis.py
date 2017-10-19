class StackValueAnalysis(object):
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


    def __init__(self):
        self.stacks = {}
        # discovered_targets: src -> [dst]
        self.discovered_targets = {}

    def _update_stack(self, bb, stack):
        last_jump = None
        for (ins, _) in bb.__iter__():
            last_jump = None
            op = str(ins[0]).replace(' ', '')
            # push X: add X to the stack
            if op.startswith('PUSH'):
                stack.append(ins[1])
            # swap i, swap the i-th element with the first
            elif op.startswith('SWAP'):
                nth_elem = int(op[4])
                top = stack[-1]
                elem = stack[-1-nth_elem]
                stack[-1] = elem
                stack[-1-nth_elem] = top
            # dup i: copy the i-th element to the top
            elif op.startswith('DUP'):
                nth_elem = int(op[3])
                dup = stack[-nth_elem]
                stack.append(dup)
            # We compute AND X, Y if X Y are integer
            elif op == 'AND':
                v1 = stack[-1]
                v2 = stack[-2]
                stack = stack[:-2]
                if v1 is not None and v2 is not None:
                    v1 = long(str(v1), 16)
                    v2 = long(str(v2), 16)
                    stack.append(hex(v1 & v2))
                else:
                    stack.append(None)
            # Record the last value used by the jump
            elif op == 'JUMP' or op == 'JUMPI':
                last_jump = stack[-1]
                stack = stack[:-1]
            # For all the other opcode: remove
            # the pop elements, and push None elements
            else:
                (n_pop, n_push) = self.table[op]
                if n_pop:
                    stack = stack[:-n_pop]
                for _ in xrange(0, n_push):
                    stack.append(None)

        return (stack, last_jump)

    def _transfer_func(self, bb, bb_saw, father_stack):
        addr = bb.start
        # FIXME (theo) what is 2 here?
        if bb_saw.count(addr) > 2:
            return
        bb_saw += [addr]

        stack = list(father_stack)

        #self.func.set_comment(bb.start, "STACK "+ str(stack))
        (stack, last_jump) = self._update_stack(bb, stack)
        # self.func.set_comment(bb.end-1, "STACK "+ str(stack))

        self.stacks[addr] = stack

        for son in bb.outgoing_edges:
            son = son.target
            self._transfer_func(son, bb_saw, stack)

        # check if the last instruction is a JUMP
        item = bb.__iter__()
        for ins in item:
            pass


        op = str(ins[0][0]).replace(' ', '')
        if op == 'JUMP':
            src = bb.end-1
            dst = long(str(last_jump), 16)
            if src not in self.discovered_targets:
                self.discovered_targets[src] = set()
            self.discovered_targets[src].add(dst)
        if op == 'JUMPI':
            src = bb.end-1
            dst = long(str(last_jump), 16)
            if src not in self.discovered_targets:
                self.discovered_targets[src] = set()
            self.discovered_targets[src].add(dst)
            ## Add the next instruction as target, as JUMPI
            dst = src + 2
            if src not in self.discovered_targets:
                self.discovered_targets[src] = set()
            self.discovered_targets[src].add(dst)



    def explore(self, bb):
        """The result of the analysis is in self.discovered_targets
        """
        self._transfer_func(bb, [], [])

def function_dynamic_jump_start(view, func):
    if func.arch.name != 'evm':
        print "This plugin works only for EVM bytecode"
        return
    targets_found = {}
    # we loop until no more targets are found or an error occured
    while True:
        # FIXME (theo) why initialize a new class here-> can we put it
        # outside of the loop?R
        sv = StackValueAnalysis()
        error = False
        try:
            sv.explore(func.basic_blocks[0])
        except:
            # error if the analysis does not start at address 0x0
            error = True
        new_targets = sv.discovered_targets
        if new_targets != targets_found:
            for src, dst in new_targets.iteritems():
                branches = map(lambda x: (func.arch, x), dst)
                func.set_user_indirect_branches(src, branches)
            targets_found = new_targets
            view.update_analysis_and_wait()
        else:
            break
        if error:
            break
