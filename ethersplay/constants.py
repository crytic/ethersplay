ADDR_SZ = 32

# BinaryNinja LowLevelIL does not support multiple address spaces. However, the
# EVM implements a Harvard Architecture, where code and data is separated. In
# the EVM case there are actually 3 address spaces: code, memory and storage.
#
# We must take care that we don't mix addresses of the different address
# spaces. We do this with a crude hack:
# The contents of memory are placed into a virtual section starting at 2**256.
# Theoretically the PC of a contract can go up to 2**256. So we just use
# the next available address as the start of memory. In the binary ninja IL we
# just add the start of the memory as a offset to each value that's used as
# address for MSTORE/MLOAD
MEMORY_START = 2**256
MEMORY_PTR_SZ = 33
MEMORY_SZ = 2**256
# The storage address space is handled similarly to memory. Starting simply
# right after the memory address space.
STORAGE_START = 2**257
STORAGE_SZ = 2**256 * 32
STORAGE_PTR_SZ = 33

EXT_ADDR_SZ = STORAGE_PTR_SZ

# apparently binary ninja does not support memory offsets greater than 2**64-1
# (so internal pointer size is apparently 64-bit)...
MEMORY_START = 2**32
MEMORY_SIZE = 2**16
