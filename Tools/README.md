# WebAssembly parser for Kaitai.io #


## Requirements ##

  * `emcc` from [EmScripten compiler suite](https://github.com/kripken/emscripten). Build instructions can be
    found [here](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html)
  * [`kaitai-struct`](http://kaitai.io/) and its Python module

``` bash
# for debian-based Linux systems
$ sudo apt-key adv --keyserver hkp://pool.sks-keyservers.net --recv 379CE192D401AB61
$ echo "deb https://dl.bintray.com/kaitai-io/debian jessie main" | sudo tee /etc/apt/sources.list.d/kaitai.list
$ sudo apt update && sudo apt install kaitai-struct-compiler
$ pip3 install --user -r ./requirements.txt
```


## Tests ##

`make test` will compile everything and disassemble a test WASM compiled "print
(Hello World)" file.

``` bash
$ make test
kaitai-struct-compiler -t python  webassembly.ksy
emcc tests/hello.c -s WASM=1 -o tests/hello.html
./wasm-disassembler.py tests/hello.wasm
[+] sub_0000 {
00000000  23 0c             get_global 0xc
00000002  21 01             set_local 0x1
00000004  23 0c             get_global 0xc
00000006  20 00             get_local 0x0
00000008  6a                i32.add
00000009  24 0c             set_global 0xc
0000000b  23 0c             get_global 0xc
0000000d  41 0f             i32.const 0xf
0000000f  6a                i32.add
}
[...]
```
