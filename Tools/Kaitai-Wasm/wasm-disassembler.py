#!/usr/bin/python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-


__author__    =   "Christophe Alladoum"
__version__   =   "0.1"
__licence__   =   "WTFPL v.2"
__file__      =   "wasm-disassembler.py"
__desc__      =   """WebAssembly file disassembler, based on Kaitai.io structure parser."""
__usage__     =   """
{3} version {0}, {1}
by {2}
syntax: {3} [options] args
""".format(__version__, __licence__, __author__, __file__)


import sys, os, argparse, struct, binascii

# katai-generated modules
try:
    from kaitaistruct import KaitaiStream, BytesIO
except ImportError:
    print("[-] Missing kaitai.io module")
    print("[-] Did you install: python -m pip install kaitaistruct")
    sys.exit(1)

try:
    import webassembly, vlq_base128_le
except ImportError:
    print("[-] Missing Webassembly module")
    print("[-] Did you run: ksc -t python webassembly.ksy")
    sys.exit(1)

# external pip modules
import hexdump

verbose = False

class WasmInstruction:
    mnemonic = None
    operands = []
    length = 0
    raw = bytearray()

    def __init__(self, data):
        opcode = data[0]
        if not opcode in opcodes:
            raise Exception("Invalid opcode {:02x}".format(opcode))

        self.mnemonic, nb_arg, arg_funcs = opcodes[opcode]

        length = 0
        args = []

        if nb_arg > 0:

            if self.mnemonic == "br_table":
                length, args = branch_table(data[1:])

            else:
                for i in range(nb_arg):
                    func = arg_funcs[i]
                    l, v = func(data[1+length:])
                    length += l
                    args.append("%#x" % v)

        self.operands = args
        self.length   = 1 + length
        self.raw      = data[0 : self.length]
        return

    def __str__(self):
        return "{} {}".format(self.mnemonic, ','.join(self.operands))

    @property
    def hexdump(self):
        return " ".join(["{:02x}".format(_) for _ in self.raw])


def varint(i):
    io = KaitaiStream(BytesIO(i))
    res = vlq_base128_le.VlqBase128Le(io)
    return res.len, res.value

def u8(i):
    return 1, struct.unpack("<B", i[0:1])[0]

def u16(i):
    return 2, struct.unpack("<H", i[0:2])[0]

def u32(i):
    return 4, struct.unpack("<I", i[0:4])[0]

def u64(i):
    return 8, struct.unpack("<Q", i[0:8])[0]

def block_type(i):
    return u8(i)

def branch_table(i):
    target_table = []
    total_length, target_count = varint(i)
    for _ in range(target_count + 1):
        _l, _c = varint(i[total_length:])
        total_length+=_l
        target_table.append("%#x" % _c)

    return total_length, target_table


opcodes = {
    # Control flow operators
    0x00: ("unreachable", 0, []),
    0x01: ("nop", 0, []),
    0x02: ("block", 1, [block_type,]),
    0x03: ("loop",1, [block_type,]),
    0x04: ("if",1, [block_type,]),
    0x05: ("else",0, []),
    0x0b: ("end",0, []),
    0x0c: ("br", 1, [varint, ]),
    0x0d: ("br_if", 1, [varint, ]),
    0x0e: ("br_table", 1, [branch_table, ]),
    0x0f: ("return",0,[]),

    # Call operators
    0x10: ("call", 1, [varint, ]),
    0x11: ("call_indirect", 1, [varint, ]),

    # Parametric operators
    0x1a: ("drop", 0, []),
    0x1b: ("select", 0, []),

    # Variable access
    0x20: ("get_local", 1, [varint, ]),
    0x21: ("set_local", 1, [varint, ]),
    0x22: ("tee_local", 1, [varint, ]),
    0x23: ("get_global", 1, [varint, ]),
    0x24: ("set_global", 1, [varint, ]),

    # Memory-related operators
    0x28: ("i32.load", 2, [varint, varint, ]),
    0x29: ("i64.load", 2, [varint, varint, ]),
    0x2a: ("f32.load", 2, [varint, varint, ]),
    0x2b: ("f64.load", 2, [varint, varint, ]),
    0x2c: ("i32.load8_s", 2, [varint, varint, ]),
    0x2d: ("i32.load8_u", 2, [varint, varint, ]),
    0x2e: ("i32.load16_s", 2, [varint, varint, ]),
    0x2f: ("i32.load16_u", 2, [varint, varint, ]),
    0x30: ("i64.load8_s", 2, [varint, varint, ]),
    0x31: ("i64.load8_u", 2, [varint, varint, ]),
    0x32: ("i64.load16_s", 2, [varint, varint, ]),
    0x33: ("i64.load16_u", 2, [varint, varint, ]),
    0x34: ("i64.load32_s", 2, [varint, varint, ]),
    0x35: ("i64.load32_u", 2, [varint, varint, ]),
    0x36: ("i32.store", 2, [varint, varint, ]),
    0x37: ("i64.store", 2, [varint, varint, ]),
    0x38: ("f32.store", 2, [varint, varint, ]),
    0x39: ("f64.store", 2, [varint, varint, ]),
    0x3a: ("i32.store8", 2, [varint, varint, ]),
    0x3b: ("i32.store16", 2, [varint, varint, ]),
    0x3c: ("i64.store8", 2, [varint, varint, ]),
    0x3d: ("i64.store16", 2, [varint, varint, ]),
    0x3e: ("i64.store32", 2, [varint, varint, ]),
    0x3f: ("current_memory", 1, [varint, ]),
    0x40: ("grow_memory", 1, [varint, ]),

    # Constants
    0x41: ("i32.const", 1, [varint, ]),
    0x42: ("i64.const", 1, [varint, ]),
    0x43: ("f32.const", 1, [u32, ]),
    0x44: ("f64.const", 1, [u64, ]),

    # Comparison operators
    0x45: ("i32.eqz", 0, []),
    0x46: ("i32.eq", 0, []),
    0x47: ("i32.ne", 0, []),
    0x48: ("i32.lt_s", 0, []),
    0x49: ("i32.lt_u", 0, []),
    0x4a: ("i32.gt_s", 0, []),
    0x4b: ("i32.gt_u", 0, []),
    0x4c: ("i32.le_s", 0, []),
    0x4d: ("i32.le_u", 0, []),
    0x4e: ("i32.ge_s", 0, []),
    0x4f: ("i32.ge_u", 0, []),
    0x50: ("i64.eqz", 0, []),
    0x51: ("i64.eq", 0, []),
    0x52: ("i64.ne", 0, []),
    0x53: ("i64.lt_s", 0, []),
    0x54: ("i64.lt_u", 0, []),
    0x55: ("i64.gt_s", 0, []),
    0x56: ("i64.gt_u", 0, []),
    0x57: ("i64.le_s", 0, []),
    0x58: ("i64.le_u", 0, []),
    0x59: ("i64.ge_s", 0, []),
    0x5a: ("i64.ge_u", 0, []),
    0x5b: ("f32.eq", 0, []),
    0x5c: ("f32.ne", 0, []),
    0x5d: ("f32.lt", 0, []),
    0x5e: ("f32.gt", 0, []),
    0x5f: ("f32.le", 0, []),
    0x60: ("f32.ge", 0, []),
    0x61: ("f64.eq", 0, []),
    0x62: ("f64.ne", 0, []),
    0x63: ("f64.lt", 0, []),
    0x64: ("f64.gt", 0, []),
    0x65: ("f64.le", 0, []),
    0x66: ("f64.ge", 0, []),

    # Numeric operators
    0x67: ("i32.clz", 0, []),
    0x68: ("i32.ctz", 0, []),
    0x69: ("i32.popcnt", 0, []),
    0x6a: ("i32.add", 0, []),
    0x6b: ("i32.sub", 0, []),
    0x6c: ("i32.mul", 0, []),
    0x6d: ("i32.div_s", 0, []),
    0x6e: ("i32.div_u", 0, []),
    0x6f: ("i32.rem_s", 0, []),
    0x70: ("i32.rem_u", 0, []),
    0x71: ("i32.and", 0, []),
    0x72: ("i32.or", 0, []),
    0x73: ("i32.xor", 0, []),
    0x74: ("i32.shl", 0, []),
    0x75: ("i32.shr_s", 0, []),
    0x76: ("i32.shr_u", 0, []),
    0x77: ("i32.rotl", 0, []),
    0x78: ("i32.rotr", 0, []),
    0x79: ("i64.clz", 0, []),
    0x7a: ("i64.ctz", 0, []),
    0x7b: ("i64.popcnt", 0, []),
    0x7c: ("i64.add", 0, []),
    0x7d: ("i64.sub", 0, []),
    0x7e: ("i64.mul", 0, []),
    0x7f: ("i64.div_s", 0, []),
    0x80: ("i64.div_u", 0, []),
    0x81: ("i64.rem_s", 0, []),
    0x82: ("i64.rem_u", 0, []),
    0x83: ("i64.and", 0, []),
    0x84: ("i64.or", 0, []),
    0x85: ("i64.xor", 0, []),
    0x86: ("i64.shl", 0, []),
    0x87: ("i64.shr_s", 0, []),
    0x88: ("i64.shr_u", 0, []),
    0x89: ("i64.rotl", 0, []),
    0x8a: ("i64.rotr", 0, []),
    0x8b: ("f32.abs", 0, []),
    0x8c: ("f32.neg", 0, []),
    0x8d: ("f32.ceil", 0, []),
    0x8e: ("f32.floor", 0, []),
    0x8f: ("f32.trunc", 0, []),
    0x90: ("f32.nearest", 0, []),
    0x91: ("f32.sqrt", 0, []),
    0x92: ("f32.add", 0, []),
    0x93: ("f32.sub", 0, []),
    0x94: ("f32.mul", 0, []),
    0x95: ("f32.div", 0, []),
    0x96: ("f32.min", 0, []),
    0x97: ("f32.max", 0, []),
    0x98: ("f32.copysign", 0, []),
    0x99: ("f64.abs", 0, []),
    0x9a: ("f64.neg", 0, []),
    0x9b: ("f64.ceil", 0, []),
    0x9c: ("f64.floor", 0, []),
    0x9d: ("f64.trunc", 0, []),
    0x9e: ("f64.nearest", 0, []),
    0x9f: ("f64.sqrt", 0, []),
    0xa0: ("f64.add", 0, []),
    0xa1: ("f64.sub", 0, []),
    0xa2: ("f64.mul", 0, []),
    0xa3: ("f64.div", 0, []),
    0xa4: ("f64.min", 0, []),
    0xa5: ("f64.max", 0, []),
    0xa6: ("f64.copysign", 0, []),

    # Conversions
    0xa7: ("i32.wrap/i64", 0, []),
    0xa8: ("i32.trunc_s/f32", 0, []),
    0xa9: ("i32.trunc_u/f32", 0, []),
    0xaa: ("i32.trunc_s/f64", 0, []),
    0xab: ("i32.trunc_u/f64", 0, []),
    0xac: ("i64.extend_s/i32", 0, []),
    0xad: ("i64.extend_u/i32", 0, []),
    0xae: ("i64.trunc_s/f32", 0, []),
    0xaf: ("i64.trunc_u/f32", 0, []),
    0xb0: ("i64.trunc_s/f64", 0, []),
    0xb1: ("i64.trunc_u/f64", 0, []),
    0xb2: ("f32.convert_s/i32", 0, []),
    0xb3: ("f32.convert_u/i32", 0, []),
    0xb4: ("f32.convert_s/i64", 0, []),
    0xb5: ("f32.convert_u/i64", 0, []),
    0xb6: ("f32.demote/f64", 0, []),
    0xb7: ("f64.convert_s/i32", 0, []),
    0xb8: ("f64.convert_u/i32", 0, []),
    0xb9: ("f64.convert_s/i64", 0, []),
    0xba: ("f64.convert_u/i64", 0, []),
    0xbb: ("f64.promote/f32", 0, []),

    # Reinterpretations
    0xbc: ("i32.reinterpret/f32", 0, []),
    0xbd: ("i64.reinterpret/f64", 0, []),
    0xbe: ("f32.reinterpret/i32", 0, []),
    0xbf: ("f64.reinterpret/i64", 0, []),
}


def get_code_section_data(w):
    for s in w.sections.sections:
        if s.header.id == w.PayloadType.code_payload:
            return s.payload_data
    return None


def disassemble_blocks(code, *args, **kwargs):
    global verbose

    if verbose:
        nb_blocks = len(code.bodies)
        print("[+] %d functions" % nb_blocks)

    for i, block in enumerate(code.bodies):
        raw_data = block.data.code
        disassemble_block(raw_data, i, args, kwargs)

    return


def disassemble_block(raw, idx, *args, **kwargs):
    stream = raw[:]

    print("[+] sub_%04x {" % idx)

    if kwargs.get("show_as_hexdump", False) == True:
        hexdump.hexdump(stream)

    else:
        idx = 0
        while idx < len(stream):
            insn = WasmInstruction(stream[idx:])
            print("{:08x}  {:16s}  {}".format(idx, insn.hexdump, str(insn), ))
            idx += insn.length
    print("}")

    del stream
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage = __usage__,
                                     description = __desc__)

    parser.add_argument("--raw", default=False,
                        action="store_true", dest="show_as_hexdump",
                        help="Show blocks as raw hexdump instead of instructions")

    parser.add_argument("-f", "--function-number", type=int, dest="funcnum",
                        help="Only disassemble the function")

    parser.add_argument("-v", "--verbose", default=False,
                        action="store_true", dest="verbose",
                        help="Increments verbosity")

    parser.add_argument("wasm_file", help="WASM file to disassemble")

    args = parser.parse_args()
    verbose = args.verbose

    assert( os.access(args.wasm_file, os.R_OK) )

    fd = open(args.wasm_file, 'rb')
    wasm = webassembly.Webassembly.from_file(args.wasm_file)
    assert( wasm.magic == b"\0asm" )
    assert( wasm.version == 0x01 )

    if verbose:
        print("[+] WASM '%s' has %d sections" % (args.wasm_file, len(wasm.sections.sections)))

    code = get_code_section_data(wasm)
    assert( code is not None)

    if verbose:
        print("[+] Code is at {:#x}".format(wasm._io.pos()))

    disassemble_blocks(code, show_as_hexdump=args.show_as_hexdump, wasm=wasm, fd=fd)
    sys.exit(0)
