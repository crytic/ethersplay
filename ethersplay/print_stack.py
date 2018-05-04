from binaryninja import log_error


def function_printStack_start(view, func):
    try:
        stackOut = view.query_metadata(hex(func.start)+".out")
    except KeyError:
        log_error(
            "Stack information is not available for {}".format(hex(func.start))
        )
        return

    for (k, vals) in stackOut.iteritems():
        vals = [[long(y) for y in x[1::]] if x[0] else "Unknown" for x in vals]
        func.set_comment(long(k), "Stack {!r}".format(vals[-10::]))
