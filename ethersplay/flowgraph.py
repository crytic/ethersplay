from binaryninja import BranchType, FlowGraph, FlowGraphNode, InstructionTextTokenType, DisassemblyTextLine

_graphs = list()

def render_flowgraphs(view):
    global _graphs
    for function in view.functions:
        g = function.create_graph()
        g.layout_and_wait()

        f = FlowGraph()
        _graphs.append(f)
        f.function = function
        f_bbs = {}

        for node in g.nodes:
            n = FlowGraphNode(f)

            for line in node.lines:
                if line.tokens[0].type == InstructionTextTokenType.AnnotationToken:
                    n.lines += [DisassemblyTextLine(line.tokens, line.address)]
                else:
                    n.lines += [DisassemblyTextLine(line.tokens[:next((i for i in range(len(line.tokens)) if line.tokens[i].type == InstructionTextTokenType.AnnotationToken), None)], line.address)]

                f_bbs[line.address] = n

            f.append(n)
        
        for i in range(len(f.nodes)):
            is_jumpi = 'JUMPI' in str(f.nodes[i].lines[-1])

            for edge in g.nodes[i].outgoing_edges:
                if edge.type == BranchType.IndirectBranch and is_jumpi:
                    f.nodes[i].add_outgoing_edge(BranchType.TrueBranch, f_bbs[edge.target.basic_block.start])
                else:
                    f.nodes[i].add_outgoing_edge(edge.type, f_bbs[edge.target.basic_block.start])

        f.show(function.name)