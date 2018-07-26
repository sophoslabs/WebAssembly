# WebAssembly module for IDA Pro #

To support `.wasm` parsing in IDA Pro, it is required to have IDA Pro 7+ with IDAPython. The installation can be done by copying the files
`wasm_processor.py` (respectively `wasm_loader.py`) into the following directories:

 - `C:\Program Files\IDA 7.x\procs` (resp. `C:\Program Files\IDA 7.x\loaders`)  for a system-wide installation (need Admin privileges)
 - `%APPDATA%\Hex Rays\IDA\procs` (resp. `%APPDATA%\Hex Rays\IDA\loaders`)  for a user-specific installation

![preview.png](https://i.imgur.com/ROf2pXM.png)


## Known bugs ##

 - Since WASM uses function indexes and not addresses for function calls, the xref support for `call` instructions is not working correctly
 - Exports tab does not uses the WASM function declaration
 - Imports tab does not uses the WASM header

