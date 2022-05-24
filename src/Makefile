EMCC	=	emcc

.PHONY: all clean

%.html: %.c
	$(EMCC) -O0 $^ -s WASM=1 -o $@

%.py: %.ksy
	kaitai-struct-compiler -t python  $^

%.js: %.ksy
	kaitai-struct-compiler -t javascript $^

all: webassembly.py
	make -C tests all

clean:
	rm -fr -- __pycache__ *.pyc webassembly.py vlq_base128_le.py

test: webassembly.py tests/hello.html
	./wasm-disassembler.py tests/hello.wasm
