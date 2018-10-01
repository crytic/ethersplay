import binaryninja

# This does not have an associated fix yet, on dev or otherwise
def IndirectBranchInfo__eq__(self, value):
    if not isinstance(value, binaryninja.IndirectBranchInfo):
        return False

    return (self.source_arch, self.source_addr, self.dest_arch, self.dest_addr) == (value.source_arch, value.source_addr, value.dest_arch, value.dest_addr)


binaryninja.function.IndirectBranchInfo.__eq__ = IndirectBranchInfo__eq__


# This does not have an associated fix yet, on dev or otherwise
def IndirectBranchInfo__hash__(self):
    return hash(self.source_arch, self.source_addr, self.dest_arch, self.dest_addr)


binaryninja.function.IndirectBranchInfo.__hash__ = IndirectBranchInfo__hash__
