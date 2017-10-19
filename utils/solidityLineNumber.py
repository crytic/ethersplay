"""
    Module matching EVM address <-> Soldity source code
"""
import os
import json
import re
import math

class SolidityLineNumber(object):
    """
        This module matches the EVM bytecode to its source code
        It takes as input the asm-json representation of the source code
        solc --asm-json test.sol > test.asm.json
        test.sol and test.asm.json have to be in the same directory
    """

    def __init__(self, filename, workspace=""):
        self.filename = filename
        self.workspace = workspace
        self.contracts = {}
        self._parse()
        self._compute_line_number()


    def _parse(self):
        f = open(os.path.join(self.workspace, self.filename))
        buf = f.read()

        # FIXME add all the instructions in each contract!
        MAGIC = "==="
        while buf:
            begin = buf.find(MAGIC)
            end = buf.find('\n}\n') + len(MAGIC)
            if end < len(MAGIC):
                # end of the file
                end = buf.rfind('\n}') + len(MAGIC)
                if end < len(MAGIC):
                    break
            contract = buf[begin:end]
            filename, contract_name = self._get_name(contract)
            # not totally sure which contract should be use
            # XXX (theo) seems like c2 is legacy ASM?
            c1, _ = self._get_contracts(contract)
            self._save_node(c1['.code'], filename, contract_name)
            buf = buf[end::]
        f.close()

    @staticmethod
    def _get_name(contract):
        ## ======= X.sol:Y =======
        ## -> X.sol , Y
        r = re.compile(r'([a-zA-Z0-9_.]*):(\w*)')
        res = r.search(contract)
        assert len(res.groups()) == 2
        filename = res.group(1)
        contract_name = res.group(2)
        return (filename, contract_name)

    @staticmethod
    def _get_contracts(contract):
        # { X }{ Y }
        # -> X, Y
        r = re.compile('{(.*)}{(.*)}', re.DOTALL)
        res = r.search(contract)
        assert len(res.groups()) == 2
        c1 = json.loads('{'+res.group(1)+'}')
        c2 = json.loads('{'+res.group(2)+'}')
        return (c1, c2)

    @staticmethod
    def _get_size_push_tag(code):
        # If there is no tag >9, returns 1, else returns 2
        for c in code:
            if c['name'] == 'tag':
                if len(c['value']) > 1:
                    return 2
        return 1


    def _save_node(self, code, filename, contract_name):
        addr = 0
        # push [tag] can be push1 or push2, ..
        # it seems to depend on the number of tag
        size_push_tag = self._get_size_push_tag(code)
        for c in code:
            c['addr'] = addr
            if c['name'] == 'tag': # tag does not exist in the bytecode
                continue
            if not c['name'].startswith('PUSH'):
                addr += 1
            # push [tag]
            elif c['name'] != 'PUSH':
                addr += size_push_tag + 1
            else:
                # size = 1 + len(value) / 2
                addr += 1 + int(math.ceil(len(c['value']) / 2.))
        if contract_name not in self.contracts:
            self.contracts[contract_name] = dict()
        self.contracts[contract_name]['nodes'] = code
        self.contracts[contract_name]['filename'] = filename

    def _compute_line_number(self):
        for contract_name in self.contracts:
            contract = self.contracts[contract_name]
            filename = contract['filename']
            f = open(os.path.join(self.workspace, filename))
            buf = f.read()
            for node in contract['nodes']:
                begin = node['begin']
                end = node['end']
                line_number_begin = buf[0:begin].count('\n') + 1
                line_number_end = buf[0:end].count('\n') + 1
                node['line_number_begin'] = line_number_begin
                node['line_number_end'] = line_number_end
                node['source_description'] = buf[begin:end]
            f.close()

    def get_line(self, contract_name, addr):
        """
        Return the source code information

        Args:
            contract_name (string): The name of the contract
            addr (int): The EVM address

        Returns:
            (string, int, int, string): The filename, the begining line number,
            the ending line number, the source code description
        """
        for node in self.contracts[contract_name]['nodes']:
            if node['addr'] == addr:
                return (self.contracts[contract_name]['filename'],
                        node['line_number_begin'],
                        node['line_number_end'],
                        node['source_description'])
        return None

