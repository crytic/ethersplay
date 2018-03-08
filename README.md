# ethersplay
EVM dissassembler and related analysis tools.

![Example](/images/example.png)

- [Installation](#installation)
- [How to use](#how-to-use)
- [Automatic Analyses](#automatic-analyses)
- [Plugins](#plugins)
- [Known issues](#known-issues)

## Installation
Create a symbolic link to the Binary Ninja [plugin folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples#loading-plugins).
E.g., in macOS
```
cd ~/Library/Application\ Support/Binary\ Ninja/plugins
ln -s <your_download_location>/ethersplay/ethersplay .
```

## How to Use

Ethersplay takes as input the evm bytecode in either ascii hex encoded or raw binary format.
 
To have the bytecode of a solidity file, use solc:
- `solc --bin-runtime file.sol`: to print the bytecode of the runtime part of the contract (for most of the cases).
- `solc --bin file.sol`: to print the initialisation bytecode of the contract (constructor),

Prefix the output from solc with '0x' and then save it with the extension `.evm` or `.bytecode`.

Example using test.sol with following contents:
```test.sol:
contract Test {
    uint256 value;
    function Test() {
        value = 5;
    }
    function set_value(uint256 v) {
        value = v;
    }
    function() payable {}
}
```

Run solidity to compile:
`solc --bin-runtime test.sol`

solc prints the bytecode to stdout in the format below:
```
======= test.sol:Test =======
Binary of the runtime part:
606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063b0f2b72a146041575b005b3415604b57600080fd5b605f60048080359060200190919050506061565b005b80600081905550505600a165627a7a723058209821eec589f65821d954ad1fc884a743ae1c6ae959cfdacb08d5d9295ba630700029
```

Create test.evm with the last part of the solc output prefixed with 0x:
```test.evm:
0x606060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063b0f2b72a146041575b005b3415604b57600080fd5b605f60048080359060200190919050506061565b005b80600081905550505600a165627a7a723058209821eec589f65821d954ad1fc884a743ae1c6ae959cfdacb08d5d9295ba630700029
```

test.evm can be loaded into Binary Ninja


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

### Manticore coverage
Color the basic blocks explored through Manticore (using the `visited.txt` file).

## Known issues
- Opening more than one bytecode file generates the wrong CFG
- `EVM Source Code` was tested with solc 0.4.16. It is not compatible with other versions.
