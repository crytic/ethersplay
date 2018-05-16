# ethersplay
EVM disassembler and related analysis tools.

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

Ethersplay takes as input the evm bytecode in raw binary format. Prepend the file with the header `EVM`, as shown below:
![EVM Header](/images/evm_header.png)
 
To have the bytecode of a solidity file, use `solc`:
- `solc --bin-runtime file.sol`: to print the bytecode of the runtime part of the contract (for most of the cases).
- `solc --bin file.sol`: to print the initialisation bytecode of the contract (constructor),



Example using `test.sol` with following contents:
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
60606040523615603d576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063b0f2b72a146041575b5b5b005b3415604b57600080fd5b605f60048080359060200190919050506061565b005b806000819055505b505600a165627a7a72305820c177a64bf54a26574918ddc2201f7ab2dd8619d6c3ee87ce9aaa1eb0e0b1d4650029
```

Copy the ascii hex string, and then create a new file in Binary Ninja. Type into the file `EVM`, then right-click and select `Paste From -> Raw Hex`. The output should look identical to the earlier example image. Save this file as `test.evm` and close it. Alternatively, paste the ascii hex string into a new text file, and run the `utils/convert_bytecode.py` on that file.

`test.evm` can now be loaded into Binary Ninja.

## Automatic analyses

These analyses are launched automatically once a bytecode is loaded:

- `EVM Dynamic Jump`: Compute the targets of dynamic jumps.
- `EVM Known Hashes`: Look for known method ID hashes.
- `EVM Create Methods`: Split the contract into methods.

## Plugins

### EVM Print Stack
Add the possible stack values as comments to the code, if it has been calculated by the value-set analysis.

### EVM Source Code

Match the solidity source code to the EVM bytecode.
The plugin needs the asm json representation source code, created using:
```
solc --asm-json examples/test.sol > examples/test.asm.json
```
The source code file has to be in the same directory than the `*.asm.json` file.

### Manticore coverage
Color the basic blocks explored through Manticore (using the `visited.txt` or `*.trace` files).

## Known issues
<<<<<<< HEAD
- The `EVM Stack Value Analysis` plugin command does not work on EVM code that is not in an `EVMView` `BinaryView`.
=======
- Analysis hangs on malformed binary files.
>>>>>>> Update convert_bytecode.py and README.md
- `EVM Source Code` was tested with solc 0.4.16. It is not compatible with other versions.
