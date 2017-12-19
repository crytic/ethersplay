from binaryninja import log

def update_branches(bv, new_branches):
    """
    new_branches  is a list of (src -> [dsts])
    """
    for (src,dsts) in new_branches:
        # TODO : what if a bb belong to n functions?
        funcs = bv.get_functions_containing(src)
        # TODO: if the BB not yet explored
        # src does not belong to a function
        if not funcs:
            funcs = bv.functions
        func = funcs[0]
        existing_branches = func.get_indirect_branches_at(src)
        existing_branches = map(lambda x : (x.dest_arch, x.dest_addr), existing_branches)
        branches = map(lambda x: (func.arch, x), dsts)
        branches = list(set(branches + existing_branches))
        func.set_user_indirect_branches(src, branches)

