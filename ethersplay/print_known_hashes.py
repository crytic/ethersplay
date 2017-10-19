from known_hashes import knownHashes

class HashMatcher(object):

    def __init__(self, func):
        self.seen_bb = set()
        self.func = func
        self.hashes_found = 0

    def _explore_ins(self, bb):
        addr = bb.start
        for ins in bb.__iter__():
            details, size = ins
            if str(details[0]).startswith('PUSH'):
                val = str(details[1])
                if val in knownHashes:
                    txt = knownHashes[val]
                    self.func.set_comment(addr, txt)
                    self.hashes_found += 1
            addr += size

    def explore(self, bb):
        addr = bb.start
        if addr in self.seen_bb:
            return
        self.seen_bb.add(addr)

        self._explore_ins(bb)

        for son in bb.outgoing_edges:
            son = son.target
            self.explore(son)


def function_known_hashes_start(view, func):
    if func.arch.name != 'evm':
        print "This plugin works only for EVM bytecode"
        return
    print_known_hashes = HashMatcher(func)
    print_known_hashes.explore(func.basic_blocks[0])
    print "Found {} hashes".format(print_known_hashes.hashes_found)
