import os
import sys
import time
from binaryninja.interaction import get_open_filename_input, get_text_line_input
from binaryninja import BinaryViewType
from binaryninja import log

from binaryninja.enums import HighlightStandardColor
from binaryninja.enums import BranchType

class BinDiff(object):

    def __init__(self, f1, f2):
        self.f1 = f1
        self.f2 = f2
        self.visited = set()

        log.log(1, f1.name)
        bb1 = f1.basic_blocks[0]
        bb2 = f2.basic_blocks[0]
        self.explore_bb(bb1, bb2)

    def explore_bb(self, bb1, bb2):
        addr1 = bb1.start
        size1 = 0
        size2 = 0
        if addr1 in self.visited:
            return
        self.visited.add(addr1)
        addr2 = bb2.start
        l_bb1 = list(bb1.__iter__())
        l_bb2 = list(bb2.__iter__())

        index_max = min(len(l_bb1), len(l_bb2))
        #for ((ins1, size1,), (ins2, size2)) in zip(bb1, bb2):
        index = 0
        index2 = 0

        off_dup_swap_pop = 0
        while index < index_max:
            ins1, size1 = l_bb1[index]
            ins2, size2 = l_bb2[index2]

            if str(ins1[0]) != str(ins2[0]):
                if index + 2 < len(l_bb1):
                    (dup_ins, s1) = l_bb1[index]
                    (swap_ins, s2) = l_bb1[index+1]
                    (pop_ins, s3) = l_bb1[index+2]
                    dup_ins = str(dup_ins[0]).replace(' ', '')
                    swap_ins = str(swap_ins[0]).replace(' ', '')
                    pop_ins = str(pop_ins[0]).replace(' ', '')
                    if dup_ins == 'DUP1' and swap_ins == 'SWAP1' and pop_ins == 'POP':

                        self.f1.set_user_instr_highlight(addr1,
                                                         HighlightStandardColor.RedHighlightColor)
                        self.f1.set_user_instr_highlight(addr1+s1,
                                                         HighlightStandardColor.RedHighlightColor)
                        self.f1.set_user_instr_highlight(addr1+s1+s2,
                                                         HighlightStandardColor.RedHighlightColor)
                        addr1 += s1+s2+s3
                        off_dup_swap_pop+=3
                        index+=3
                        continue
#                    else:
#                        log.log(1, 'Diff')
#                        log.log(1, dup_ins)
#                        log.log(1, swap_ins)
#                        log.log(1, pop_ins)
                self.f1.set_comment(addr1, str(ins2))
                self.f1.set_user_instr_highlight(addr1, HighlightStandardColor.RedHighlightColor)
            elif str(ins1) != str(ins2):
                self.f1.set_comment(addr1, str(ins2))
                self.f1.set_user_instr_highlight(addr1, HighlightStandardColor.BlueHighlightColor)
            addr1 += size1
            addr2 += size2
            index = index+1
            index2 = index2+1

#        if len(l_bb1) > len(l_bb2):
        index = index - off_dup_swap_pop
        if index > index2:
            diff = index - index2
            for addr in xrange(addr1-size1, addr1-size1 + diff):
                self.f1.set_user_instr_highlight(addr, HighlightStandardColor.RedHighlightColor)
 #       elif len(l_bb1) < len(l_bb2):
        elif index < index2:
            diff = index2 - index
            txt = self.f1.get_comment_at(addr1 - size1)
            l_diff = l_bb2[index:]
            for (ins, _) in l_diff:
                txt += "\n" + str(ins)
            self.f1.set_comment(addr1-size1, txt)
            self.f1.set_user_instr_highlight(addr1-size1, HighlightStandardColor.RedHighlightColor)
        self.explore_outgoing_edges(bb1, bb2)


    def explore_outgoing_edges(self, bb1, bb2):
        bb1_out = bb1.outgoing_edges
        bb2_out = bb2.outgoing_edges
        if len(bb1_out) != len(bb2_out):
            log.log(1, 'Different number of outgoing edges? '+hex(bb1.start))
            self.f1.set_user_instr_highlight(bb1.start, HighlightStandardColor.OrangeHighlightColor)
        elif len(bb1_out) == 0:
            pass
        elif len(bb1_out) == 1:
            self.explore_bb(bb1_out[0].target, bb2_out[0].target)
        else:
            if bb1_out[0].type == BranchType.TrueBranch:
                bb1_true = bb1_out[0].target
                bb1_false = bb1_out[1].target
            else:
                bb1_true = bb1_out[1].target
                bb1_false = bb1_out[0].target
            if bb2_out[0].type == BranchType.TrueBranch:
                bb2_true = bb2_out[0].target
                bb2_false = bb2_out[1].target
            else:
                bb2_true = bb2_out[1].target
                bb2_false = bb2_out[0].target
            self.explore_bb(bb1_true, bb2_true)
            self.explore_bb(bb1_false, bb2_false)


def function_bindiff_start(view, func):
    if func.arch.name != 'evm':
        log.log(1, "This plugin works only for EVM bytecode")
        return
    filename_diff = get_open_filename_input('Bytecode to compare', "*.bytecode")
    if not filename_diff:
        return

    log.log(1, 'Load file...')
    view_diff = BinaryViewType['EVM'].open(filename_diff)
    view_diff.init()
    view_diff.update_analysis_and_wait()
    # TODO update_analysis_and_wait does not wait for all the evm analysis?
    time.sleep(20)
    func_ori = {x.name:x for x in view.functions}

    func_diff = {x.name:x for x in view_diff.functions}

    log.log(1, str(func_diff))
    func_combine = {}
    for (f_name, f_ori) in func_ori.iteritems():
        if f_name not in func_diff:
            log.log(1, "The function was not found: "+f_name)
            continue
        f_diff = func_diff[f_name]
        func_combine[f_name] = [f_ori, f_diff]

    for (f_name, (f1, f2)) in func_combine.iteritems():
        log.log(1, "Analyze "+f_name)
        BinDiff(f1, f2)
    log.log(1, 'Bindiff analysis ended')

