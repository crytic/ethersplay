# ethersplay
EVM dissassembler and related analysis tools.

- [Installation](#installation)
- [How to use](#how-to-use)
- [Automatic Analyses](#automatic-analyses)
- [Plugins](#plugins)
- [Known issues](#known-issues)

## Installation
Create a symbolic link to the Binary Ninja [plugin folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples#loading-plugins).
E.g., in macOS
```
cd ~/Library/Application\ Support/Binary\ Ninja
ln -s <your_download_location>/ethersplay/ethersplay .
```

## How to Use

The file has to contain the bytecode in raw format. You can convert the text representation of the bytecode using `utils/convert_bytecode.py`:
```bash
$ cat examples/test.evm
60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063448f30a314610049578063b61d27f61461005e575b600080fd5b341561005457600080fd5b61005c6100d0565b005b341561006957600080fd5b6100b2600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091908035906020019082018035906020019190919290505061013b565b60405180826000191660001916815260200191505060405180910390f35b7ff9fbd55454309325ccadd998a641a1dfe7cd888eea26c0ae93b95992a13ac1446040518080602001828103825260078152602001807f6e6f7468696e670000000000000000000000000000000000000000000000000081525060200191505060405180910390a15b565b600061017a600161016c343073ffffffffffffffffffffffffffffffffffffffff163161024490919063ffffffff16565b61025e90919063ffffffff16565b5060008383905014156101de578473ffffffffffffffffffffffffffffffffffffffff168484846040518083838082843782019150509250505060006040518083038185876187965a03f19250505015156101d457600080fd5b61023c565b61023b565b84600080836000191660001916815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b5b949350505050565b600082821115151561025257fe5b81830390505b92915050565b600082821115151561026c57fe5b81830390505b929150505600a165627a7a72305820810579e0bc6d4b9345e309d56903d908914fafd2efc0f606473377675a3347100029
$ python utils/convert_bytecode.py examples/test.evm examples/test.bytecode
```
`examples/test.bytecode` can then be used with binary ninja.


## Automatic analyses

These analyses are launched automatically once a bytecode is loaded:

- `EVM Dynamic Jump`: Compute the targets of dynamic jumps.
- `EVM Known Hashes`: Look for known method ID hashes.
- `EVM Create Methods`: Split the contract into methods.

## Plugins

### EVM Source Code

Match the solidity source code to the EVM bytecode.
The plugin needs the asm json representation source code, created using:
```
solc --asm-json examples/test.sol > examples/test.asm.json
```
The source code file has to be in the same directory than the `*.asm.json` file.

### EVM Bindiff
Find the difference between two bytecodes.

### Manticore coverage
Color the basic blocks explored through Manticore (using the `visited.txt` file).

## Known issues
- Opening more than one bytecode file generates the wrong CFG
- `EVM Source Code` was tested with solc 0.4.16. It is not compatible with other versions.
- `EVM Bindiff` is a work in progress. It contains several bugs.
