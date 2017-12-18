#!/usr/bin/python
import sys
#import re

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Usage: python convert_bytecode.py input.evm output.bytecode"
        exit(0)

    filename_input = sys.argv[1]
    filename_output = sys.argv[2]

    f = open(filename_input, 'r')
    code = f.read()
    f.close()

    code = code.replace('\n', '').decode('hex')

    f = open(filename_output, 'wb')
    f.write(code)
    f.close()

