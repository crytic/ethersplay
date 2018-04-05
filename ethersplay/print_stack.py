from binaryninja.interaction import get_open_filename_input, get_text_line_input
from binaryninja import HighlightStandardColor
from binaryninja import log

class PrintStack(object):
    '''
        Print up to 10 values of the stack
    '''

    def __init__(self, view, func):
        self.view = view
        self.func = func

    def printStack(self):
        stackOut = self.view.query_metadata(self.func.name+".out")

        for (k, vals) in stackOut.iteritems():
            vals = [[long(y) for y in x[1::]] if x[0] else None for x in vals]
            self.func.set_comment(long(k), "Stack %s"%str(vals[-10::]))


def function_printStack_start(view, func):
    detector = PrintStack(view, func)
    detector.printStack()

