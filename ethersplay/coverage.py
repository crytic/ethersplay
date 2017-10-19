from binaryninja.interaction import get_open_filename_input, get_text_line_input
from binaryninja import HighlightStandardColor
from binaryninja import log

blue = HighlightStandardColor.BlueHighlightColor

class Coverage(object):

    def __init__(self, view, visited):
        self.bb_seen = []
        self.view = view
        self.color_visited(visited)

    def color_visited(self, visited):
        with open(visited,'r') as f:
            for line in f:
                index = line.find(':') + 1
                line = line[index:]
                log.log(1, line)
                self.color_at(int(line, 16))

    def color_at(self, addr):
        bbs = self.view.get_basic_blocks_at(addr)
        for bb in bbs:
            func = bb.function
            func.set_auto_instr_highlight(addr, blue)



def function_coverage_start(view):
    visited = get_open_filename_input('Visited file', "visited.txt")
    Coverage(view, visited)

