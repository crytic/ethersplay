from binaryninja.interaction import get_open_filename_input, get_text_line_input
from binaryninja import HighlightStandardColor
from binaryninja import log

blue = HighlightStandardColor.BlueHighlightColor

class GraphColorer(object):

    def __init__(self, view):
        self.bb_seen = []
        self.view = view

    def color(self, visited):
        with open(visited,'r') as f:
            for line in f:
                index = line.find(':') + 1
                addr = line[index:].split()[0]
                log.log(1, addr)
                try:
                    self.color_at(int(addr, 16))
                except ValueError:
                    # if thrown by int()
                    pass

    def color_at(self, addr):
        bbs = self.view.get_basic_blocks_at(addr)
        for bb in bbs:
            func = bb.function
            func.set_instr_highlight(addr, blue)



def function_coverage_start(view):
    visited = get_open_filename_input('visited.txt or *.trace')
    colorer = GraphColorer(view)
    colorer.color(visited)

