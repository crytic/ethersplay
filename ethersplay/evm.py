import traceback

from evm_opcodes import EVMDecoder

from binaryninja import (Architecture, RegisterInfo, InstructionInfo,
                         InstructionTextToken, BinaryView, log_info, log_error,
                         Endianness, SegmentFlag, BackgroundTaskThread, Symbol,
                         SymbolType, set_worker_thread_count, BranchType,
                         InstructionTextTokenType, log)

from create_methods import CreateMethods
from print_known_hashes import HashMatcher
from stack_value_analysis import function_dynamic_jump_start

from constants import (ADDR_SZ, EXT_ADDR_SZ, MEMORY_START, MEMORY_SZ)

from evm_llil import InstructionIL, TrapInstructions
from evm_gas import gas
import config


class EVM(Architecture):
    name = 'evm'
    address_size = EXT_ADDR_SZ
    default_int_size = ADDR_SZ
    max_instr_length = 1 + 32
    endianness = Endianness.BigEndian
    _reglist = [
        # == Execution related registers - Mutable ==
        'sp',
        'pc',
        'gas_used',
        'gas_available',
        # MSIZE is kind of a weird instruction, it returns the "size" of the
        # current memory in use. of course a contract can mstore basically
        # anywhere in memory
        'msize',

        # == environment information (immutable registers) ==
        'address',
        'caller',
        'callvalue',
        'calldatasize',
        'gasprice'
        'origin',

        # == block information (immutable registers) ==
        'coinbase',
        'timestamp',
        'number',
        'difficulty',
        'gaslimit',

        # special register which is set for "system calls" into the EVM
        'evm_call_nr',
        'evm_call_arg0',
        'evm_call_arg1',
        'evm_call_arg2',
        'evm_call_arg3',
        'evm_call_arg4',
        'evm_call_arg5',
        'evm_call_arg6',
    ]
    regs = {x: RegisterInfo(x, ADDR_SZ) for x in _reglist}
    stack_pointer = 'sp'
    flags = []

    def decode_instruction(self, data, addr):
        instruction = EVMDecoder.decode_one(data)
        return instruction

    def perform_get_instruction_info(self, data, addr):
        instruction = EVMDecoder.decode_one(data)

        if instruction is None:
            return instruction

        result = InstructionInfo()
        result.length = instruction.size

        # Add branches
        if instruction.name in [
                'RETURN', 'REVERT', 'SUICIDE', 'INVALID', 'STOP',
                'SELFDESTRUCT'
        ]:
            result.add_branch(BranchType.FunctionReturn)
        elif instruction.name in ['JUMPI']:
            result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + 1)
        elif instruction.name in ['JUMP']:
            result.add_branch(BranchType.UnconditionalBranch)
        elif instruction.name in TrapInstructions.values():
            result.add_branch(BranchType.SystemCall)
        return result

    def perform_get_instruction_text(self, data, addr):
        instruction = EVMDecoder.decode_one(data)
        if instruction is None:
            return instruction

        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken,
                                 '{:7s}'.format(instruction.name))
        ]

        if instruction.has_operand:
            operand = instruction.operand
            tokens.append(
                InstructionTextToken((InstructionTextTokenType.IntegerToken),
                                     '{:#x}'.format(operand), operand))

        return tokens, instruction.size

    def _get_name(self, name):
        name = name.lstrip().rstrip()
        # multiple_ops = ["PUSH", "DUP", "SWAP"]
        multiple_ops = ["PUSH"]
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
        if not config.ENABLE_LLIL_LIFTING or name not in InstructionIL:
            il.append(il.unimplemented())
        else:
            ilins = InstructionIL[name](il, addr, insn.operand,
                                        insn.operand_size, insn.pops,
                                        insn.pushes)
            if isinstance(ilins, list):
                for i in [i for i in ilins if i is not None]:
                    il.append(i)
            elif ilins is not None:
                il.append(ilins)
        return insn.size

    def perform_assemble(self, code, addr):
        return None


# class EVMPlatform(Platform):
# TODO: do we want a custom platform for calling conventions (and syscall
# conventions?)


class InitialAnalysisTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Initial Analysis", True)
        self.bv = bv

    def run(self):
        run_initial_analysis(self.bv)


def analyze(completion_event):
    set_worker_thread_count(4)

    iat = InitialAnalysisTask(completion_event.view)
    iat.start()


def run_initial_analysis(view):
    view.define_auto_symbol(
        Symbol(SymbolType.FunctionSymbol, 0, "_dispatcher"))
    CreateMethods(view).explore(view.get_basic_blocks_at(0)[0])

    for f in view.functions:
        h = HashMatcher(f)
        if f.basic_blocks is not None:
            try:
                h.explore(f.basic_blocks[0])
            except IndexError:
                log_error("Failed to explore " + str(f))

    for f in view.functions:
        function_dynamic_jump_start(view, f)
    log.log(1, 'Initialization Done')


class EVMView(BinaryView):
    name = "EVM"
    long_name = "EVM"

    def __init__(self, data):

        # Check if input is a hexified string
        self.hexify = False
        if data.read(0, 2) == '0x':
            buf = (data.read(0, len(data)))[2:].strip().rstrip()
            buf_set = set()
            for c in buf:
                buf_set.update(c)
            hex_set = set(list('0123456789abcdef'))
            if buf_set <= hex_set:  # subset
                self.hexify = True
                self.raw_data = buf.decode('hex')

        if self.hexify:
            parent_view = None
        else:
            parent_view = data

        BinaryView.__init__(
            self, file_metadata=data.file, parent_view=parent_view)

        self.data = data
        self.arch = Architecture['evm']
        self.platform = self.arch.standalone_platform

    # TODO: implement perform_write
    #def perform_write(self, addr, data):
    #    pass

    def perform_read(self, addr, length):
        if self.hexify:
            try:
                the_bytes = self.raw_data[addr:addr + length]
                return the_bytes
            except:
                return None
        else:
            return BinaryView.perform_read(self, addr, length)

    def perform_is_valid_offset(self, addr):
        if self.hexify:
            return addr < len(self.raw_data)
        else:
            return BinaryView.perform_is_valid_offset(self, addr)

    def perform_get_length(self):
        if self.hexify:
            return len(self.raw_data)
        else:
            return BinaryView.perform_get_length(self)

    def init(self):
        try:
            if self.hexify:
                file_size = len(self.raw_data)
            else:
                file_size = len(self.data)
            self.entry_addr = 0
            self.add_entry_point(self.entry_addr)
            self.add_auto_segment(
                0, file_size, 0, file_size,
                (SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable))

            self.add_auto_section("memory", MEMORY_START, MEMORY_SZ)
            # self.add_auto_section("storage", STORAGE_START, STORAGE_SZ)

            self.add_analysis_completion_event(analyze)

            return True
        except Exception as e:
            log_error(traceback.print_stack())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr

    def perform_get_address_size(self):
        return self.arch.address_size

    @staticmethod
    def is_valid_for_data(data):
        file_name = data.file.filename
        if file_name.endswith('.bytecode'):
            return True
        if file_name.endswith('.evm'):
            return True
