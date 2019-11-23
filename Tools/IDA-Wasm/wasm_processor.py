# -*- mode: python -*-
# -*- coding: utf-8 -*-
#
# WebAssembly processor for IDA 7.+
#
#
# To install, simply copy `wasm_processor.py` in :
#  - C:\Program Files\IDA 7.1\procs  (system-wide)
#  - %APPDATA%\Hex Rays\IDA\procs  (user only)
#
# TODO:
# - handle xref to function indexes
# - fix incorrect block parsing
# - fill Exports tab based on wasm function declaration
# - fill Imports tab from WASM header
#


from __future__ import print_function

import collections
import math
import io
import struct

from idaapi import *


#
# If True, the disassembly will take way longer
#
DEBUG = False


FL_SIGNED = 0x000001
UA_MAXOP  = 8


def log(x): print(x)
def dbg(x): log("[*] {:s}".format(x)) if DEBUG else None
def ok(x): log("[+] {:s}".format(x))
def err(x): log("[-] {:s}".format(x))
def warn(x): log("[!] {:s}".format(x))


class DecodingError(Exception):
    pass


def varint_decode_stream(stream):
    def _read_one(stream):
        c = stream.read(1)
        if c == '':
            raise EOFError("Unexpected EOF while reading bytes")
        return ord(c)

    shift = 0
    result = 0
    j = 0
    while True:
        i = _read_one(stream)
        result |= (i & 0x7f) << shift
        shift += 7
        j += 1
        if not (i & 0x80):
            break

    return j, result


def varint_decode_bytes(buf):
    return varint_decode_stream(io.BytesIO(buf))


class uint32:
    def __init__(self, raw):
        self.raw = raw[:4]
        self.value = struct.unpack("<I", self.raw)
        self.max_size = self.size = 4

class uint64:
    def __init__(self, raw):
        self.raw = raw[:8]
        self.value = struct.unpack("<Q", self.raw)
        self.max_size = self.size = 8

class varuint32:
    max_size = 4
    def __init__(self, raw):
        self.raw = raw
        self.size, self.value = varint_decode_bytes(self.raw)


class varuint64(varuint32):
    max_size = 8


class memory_immediate:
    def __init__(self, raw):
        s1, self.flags = varint_decode_bytes(raw)
        s2, self.offset = varint_decode_bytes(raw[s1:])
        self.size = s1 + s2
        self.value = self.offset


class block_type:
    def __init__(self, raw):
        self.size, self.value = varint_decode_bytes(raw)


def get_next_bytes(insn, nb):
    # horrible horrible hack
    c = ""
    old = nb
    while nb:
        c += chr(insn.get_next_byte())
        nb -= 1
    insn.size -= old
    return c


def read_until(insn, c):
    res = []
    nb = 0
    while True:
        cur = chr(insn.get_next_byte())
        nb += 1
        if cur == c:
            break
        res.append(cur)
        nb += 1
    insn.size -= nb
    return "".join(res)




#
# Some internal flags used by the decoder, emulator and output
# useless
#
FL_B         = 0x000000001 # 8 bits
FL_W         = 0x000000002 # 16 bits
FL_D         = 0x000000004 # 32 bits
FL_Q         = 0x000000008 # 64 bits
FL_OP1       = 0x000000010 # check operand 1
FL_32        = 0x000000020 # Is 32
FL_64        = 0x000000040 # Is 64
FL_NATIVE    = 0x000000080 # native call
FL_REL       = 0x000000100 # relative address
FL_CS        = 0x000000200 # Condition flag is set
FL_NCS       = 0x000000400 # Condition flag is not set
FL_INDIREC   = 0x000000800 # This is an indirect access (not immediate value)
FL_SIGNED    = 0x000001000 # This is a signed operand





class wasm_processor_t(processor_t):
    id = 0x8000 + 1337
    flag = PR_USE32 | PR_NO_SEGMOVE | PR_ADJSEGS | PRN_HEX 
    cnbits = 8
    dnbits = 8
    psnames = ["wasm"]
    plnames = ["WASM"]
    segreg_size = 0
    instruc_start = 0
    tbyte_size = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2  | AS_NOTAB,
        "uflag": 0,
        "name": "WASM Assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "pc",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    instruc = instrs  = [
        ### (name , opcode , description , ida-feature)
        ## Feature bits: https://www.hex-rays.com/products/ida/support/sdkdoc/group___c_f__.html

        # Control flow operators
        {"name": "unreachable", "opcode": 0x00, "description": "trap immediately", "feature": CF_STOP, "args": []},
        {"name": "nop", "opcode": 0x01, "description": "no operation", "feature": 0, "args": []},
        {"name": "block", "opcode": 0x02, "description": "begin a sequence of expressions, yielding 0 or 1 values", "feature": CF_JUMP, "args": [block_type, ]},
        {"name": "loop", "opcode": 0x03, "description": "begin a block which can also form control flow loops", "feature": CF_JUMP, "args": [block_type, ]},
        {"name": "if", "opcode": 0x04, "description": "begin if expression", "feature": CF_JUMP, "args": [block_type, ]},
        {"name": "else", "opcode": 0x05, "description": "begin else expression of if", "feature": 0, "args": []},
        {"name": "end", "opcode": 0x0b, "description": "end a block, loop, or if", "feature": 0, "args": []},
        {"name": "br", "opcode": 0x0c, "description": "break that targets an outer nested block", "feature": CF_JUMP, "args": [varuint32, ]},
        {"name": "br_if", "opcode": 0x0d, "description": "conditional break that targets an outer nested block", "feature": CF_JUMP, "args": [varuint32, ]},
        {"name": "br_table", "opcode": 0x0e, "description": "branch table control flow construct", "feature": CF_JUMP, "args": []},
        {"name": "return", "opcode": 0x0f, "description": "return zero or one value from this function", "feature": CF_STOP, "args": []},

        # Call operators
        {"name": "call", "opcode": 0x10, "description": "call a function by its index", "feature": CF_CALL, "args": [varuint32, ]},
        {"name": "call_indirect", "opcode": 0x11, "description": "call a function indirect with an expected signature", "feature": CF_CALL , "args": [varuint32, ]},

        # Parametric operators
        {"name": "drop", "opcode": 0x1a, "description": "ignore value", "feature": 0, "args": []},
        {"name": "select", "opcode": 0x1b, "description": "select one of two values based on condition", "feature": 0, "args": []},

        # Variable access
        {"name": "get_local", "opcode": 0x20, "description": "read a local variable or parameter", "feature": CF_USE1, "args": [varuint32, ]},
        {"name": "set_local", "opcode": 0x21, "description": "write a local variable or parameter", "feature": CF_USE1  | CF_CHG1, "args": [varuint32, ]},
        {"name": "tee_local", "opcode": 0x22, "description": "write a local variable or parameter and return the same value", "feature": CF_USE1  | CF_CHG1 | CF_JUMP, "args": [varuint32, ]},
        {"name": "get_global", "opcode": 0x23, "description": "read a global variable", "feature": CF_USE1, "args": [varuint32, ]},
        {"name": "set_global", "opcode": 0x24, "description": "write a global variable", "feature": CF_CHG1, "args": [varuint32, ]},

        # # Memory-related operators
        {"name": "i32.load"	, "opcode": 0x28,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load"	, "opcode": 0x29,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "f32.load"	, "opcode": 0x2a,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "f64.load"	, "opcode": 0x2b,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.load8_s"	, "opcode": 0x2c,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.load8_u"	, "opcode": 0x2d,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.load16_s"	, "opcode": 0x2e,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.load16_u"	, "opcode": 0x2f,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load8_s"	, "opcode": 0x30,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load8_u"	, "opcode": 0x31,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load16_s"	, "opcode": 0x32,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load16_u"	, "opcode": 0x33,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load32_s"	, "opcode": 0x34,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.load32_u"	, "opcode": 0x35,	"description": "load from memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.store"	, "opcode": 0x36,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.store"	, "opcode": 0x37,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "f32.store"	, "opcode": 0x38,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "f64.store"	, "opcode": 0x39,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.store8"	, "opcode": 0x3a,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i32.store16"	, "opcode": 0x3b,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.store8"	, "opcode": 0x3c,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.store16"	, "opcode": 0x3d,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "i64.store32"	, "opcode": 0x3e,	"description": "store to memory", "feature": CF_USE1, "args": [memory_immediate,]},
        {"name": "current_memory", "opcode": 0x3f,      "description": "query the size of memory", "feature": 0, "args": [varuint32,]},
        {"name": "grow_memory"	, "opcode": 0x40,	"description": "grow the size of memory", "feature": CF_USE1, "args": [varuint32,]},

        # # Constants
        {"name": "i32.const", "opcode": 0x41, "description": "a constant value interpreted as i32", "feature": CF_USE1, "args": [varuint32,]},
        {"name": "i64.const", "opcode": 0x42, "description": "a constant value interpreted as i64", "feature": CF_USE1, "args": [varuint64,]},
        {"name": "f32.const", "opcode": 0x43, "description": "a constant value interpreted as f32", "feature": CF_USE1, "args": [uint32, ]},
        {"name": "f64.const", "opcode": 0x44, "description": "a constant value interpreted as f64", "feature": CF_USE1, "args": [uint64, ]},

        # Comparison operators
        {"name": "i32.eqz", "opcode": 0x45, "description": "", "feature": 0, "args": []},
        {"name": "i32.eq",  "opcode": 0x46, "description": "", "feature": 0, "args": []},
        {"name": "i32.ne", "opcode": 0x47, "description": "", "feature": 0, "args": []},
        {"name": "i32.lt_s", "opcode": 0x48, "description": "", "feature": 0, "args": []},
        {"name": "i32.lt_u" , "opcode": 0x49, "description": "", "feature": 0, "args": []},
        {"name": "i32.gt_s" , "opcode": 0x4a, "description": "", "feature": 0, "args": []},
        {"name": "i32.gt_u" , "opcode": 0x4b, "description": "", "feature": 0, "args": []},
        {"name": "i32.le_s" , "opcode": 0x4c, "description": "", "feature": 0, "args": []},
        {"name": "i32.le_u" , "opcode": 0x4d, "description": "", "feature": 0, "args": []},
        {"name": "i32.ge_s" , "opcode": 0x4e, "description": "", "feature": 0, "args": []},
        {"name": "i32.ge_u" , "opcode": 0x4f, "description": "", "feature": 0, "args": []},
        {"name": "i64.eqz", "opcode": 0x50, "description": "", "feature": 0, "args": []},
        {"name": "i64.eq", "opcode": 0x51, "description": "", "feature": 0, "args": []},
        {"name": "i64.ne", "opcode": 0x52, "description": "", "feature": 0, "args": []},
        {"name": "i64.lt_s" , "opcode": 0x53, "description": "", "feature": 0, "args": []},
        {"name": "i64.lt_u" , "opcode": 0x54, "description": "", "feature": 0, "args": []},
        {"name": "i64.gt_s" , "opcode": 0x55, "description": "", "feature": 0, "args": []},
        {"name": "i64.gt_u" , "opcode": 0x56, "description": "", "feature": 0, "args": []},
        {"name": "i64.le_s" , "opcode": 0x57, "description": "", "feature": 0, "args": []},
        {"name": "i64.le_u" , "opcode": 0x58, "description": "", "feature": 0, "args": []},
        {"name": "i64.ge_s" , "opcode": 0x59, "description": "", "feature": 0, "args": []},
        {"name": "i64.ge_u" , "opcode": 0x5a, "description": "", "feature": 0, "args": []},
        {"name": "f32.eq" , "opcode": 0x5b, "description": "", "feature": 0, "args": []},
        {"name": "f32.ne" , "opcode": 0x5c, "description": "", "feature": 0, "args": []},
        {"name": "f32.lt" , "opcode": 0x5d, "description": "", "feature": 0, "args": []},
        {"name": "f32.gt" , "opcode": 0x5e, "description": "", "feature": 0, "args": []},
        {"name": "f32.le" , "opcode": 0x5f, "description": "", "feature": 0, "args": []},
        {"name": "f32.ge" , "opcode": 0x60, "description": "", "feature": 0, "args": []},
        {"name": "f64.eq" , "opcode": 0x61, "description": "", "feature": 0, "args": []},
        {"name": "f64.ne" , "opcode": 0x62, "description": "", "feature": 0, "args": []},
        {"name": "f64.lt" , "opcode": 0x63, "description": "", "feature": 0, "args": []},
        {"name": "f64.gt" , "opcode": 0x64, "description": "", "feature": 0, "args": []},
        {"name": "f64.le" , "opcode": 0x65, "description": "", "feature": 0, "args": []},
        {"name": "f64.ge" , "opcode": 0x66, "description": "", "feature": 0, "args": []},

        # Numeric operators
        {"name": "i32.clz", "opcode": 0x67, "description": "", "feature": 0, "args": []},
        {"name": "i32.ctz", "opcode": 0x68, "description": "", "feature": 0, "args": []},
        {"name": "i32.popcnt", "opcode": 0x69, "description": "", "feature": 0, "args": []},
        {"name": "i32.add", "opcode": 0x6a, "description": "", "feature": 0, "args": []},
        {"name": "i32.sub", "opcode": 0x6b, "description": "", "feature": 0, "args": []},
        {"name": "i32.mul", "opcode": 0x6c, "description": "", "feature": 0, "args": []},
        {"name": "i32.div_s", "opcode": 0x6d, "description": "", "feature": 0, "args": []},
        {"name": "i32.div_u", "opcode": 0x6e, "description": "", "feature": 0, "args": []},
        {"name": "i32.rem_s", "opcode": 0x6f, "description": "", "feature": 0, "args": []},
        {"name": "i32.rem_u", "opcode": 0x70, "description": "", "feature": 0, "args": []},
        {"name": "i32.and", "opcode": 0x71, "description": "", "feature": 0, "args": []},
        {"name": "i32.or", "opcode": 0x72, "description": "", "feature": 0, "args": []},
        {"name": "i32.xor", "opcode": 0x73, "description": "", "feature": 0, "args": []},
        {"name": "i32.shl", "opcode": 0x74, "description": "", "feature": 0, "args": []},
        {"name": "i32.shr_s", "opcode": 0x75, "description": "", "feature": 0, "args": []},
        {"name": "i32.shr_u", "opcode": 0x76, "description": "", "feature": 0, "args": []},
        {"name": "i32.rotl", "opcode": 0x77, "description": "", "feature": 0, "args": []},
        {"name": "i32.rotr", "opcode": 0x78, "description": "", "feature": 0, "args": []},
        {"name": "i64.clz", "opcode": 0x79, "description": "", "feature": 0, "args": []},
        {"name": "i64.ctz", "opcode": 0x7a, "description": "", "feature": 0, "args": []},
        {"name": "i64.popcnt", "opcode": 0x7b, "description": "", "feature": 0, "args": []},
        {"name": "i64.add", "opcode": 0x7c, "description": "", "feature": 0, "args": []},
        {"name": "i64.sub", "opcode": 0x7d, "description": "", "feature": 0, "args": []},
        {"name": "i64.mul", "opcode": 0x7e, "description": "", "feature": 0, "args": []},
        {"name": "i64.div_s", "opcode": 0x7f, "description": "", "feature": 0, "args": []},
        {"name": "i64.div_u", "opcode": 0x80, "description": "", "feature": 0, "args": []},
        {"name": "i64.rem_s", "opcode": 0x81, "description": "", "feature": 0, "args": []},
        {"name": "i64.rem_u", "opcode": 0x82, "description": "", "feature": 0, "args": []},
        {"name": "i64.and", "opcode": 0x83, "description": "", "feature": 0, "args": []},
        {"name": "i64.or", "opcode": 0x84, "description": "", "feature": 0, "args": []},
        {"name": "i64.xor", "opcode": 0x85, "description": "", "feature": 0, "args": []},
        {"name": "i64.shl", "opcode": 0x86, "description": "", "feature": 0, "args": []},
        {"name": "i64.shr_s", "opcode": 0x87, "description": "", "feature": 0, "args": []},
        {"name": "i64.shr_u", "opcode": 0x88, "description": "", "feature": 0, "args": []},
        {"name": "i64.rotl", "opcode": 0x89, "description": "", "feature": 0, "args": []},
        {"name": "i64.rotr", "opcode": 0x8a, "description": "", "feature": 0, "args": []},
        {"name": "f32.abs", "opcode": 0x8b, "description": "", "feature": 0, "args": []},
        {"name": "f32.neg", "opcode": 0x8c, "description": "", "feature": 0, "args": []},
        {"name": "f32.ceil", "opcode": 0x8d, "description": "", "feature": 0, "args": []},
        {"name": "f32.floor", "opcode": 0x8e, "description": "", "feature": 0, "args": []},
        {"name": "f32.trunc", "opcode": 0x8f, "description": "", "feature": 0, "args": []},
        {"name": "f32.nearest", "opcode": 0x90, "description": "", "feature": 0, "args": []},
        {"name": "f32.sqrt", "opcode": 0x91, "description": "", "feature": 0, "args": []},
        {"name": "f32.add", "opcode": 0x92, "description": "", "feature": 0, "args": []},
        {"name": "f32.sub", "opcode": 0x93, "description": "", "feature": 0, "args": []},
        {"name": "f32.mul", "opcode": 0x94, "description": "", "feature": 0, "args": []},
        {"name": "f32.div", "opcode": 0x95, "description": "", "feature": 0, "args": []},
        {"name": "f32.min", "opcode": 0x96, "description": "", "feature": 0, "args": []},
        {"name": "f32.max", "opcode": 0x97, "description": "", "feature": 0, "args": []},
        {"name": "f32.copysign", "opcode": 0x98, "description": "", "feature": 0, "args": []},
        {"name": "f64.abs", "opcode": 0x99, "description": "", "feature": 0, "args": []},
        {"name": "f64.neg", "opcode": 0x9a, "description": "", "feature": 0, "args": []},
        {"name": "f64.ceil", "opcode": 0x9b, "description": "", "feature": 0, "args": []},
        {"name": "f64.floor", "opcode": 0x9c, "description": "", "feature": 0, "args": []},
        {"name": "f64.trunc", "opcode": 0x9d, "description": "", "feature": 0, "args": []},
        {"name": "f64.nearest", "opcode": 0x9e, "description": "", "feature": 0, "args": []},
        {"name": "f64.sqrt", "opcode": 0x9f, "description": "", "feature": 0, "args": []},
        {"name": "f64.add", "opcode": 0xa0, "description": "", "feature": 0, "args": []},
        {"name": "f64.sub", "opcode": 0xa1, "description": "", "feature": 0, "args": []},
        {"name": "f64.mul", "opcode": 0xa2, "description": "", "feature": 0, "args": []},
        {"name": "f64.div", "opcode": 0xa3, "description": "", "feature": 0, "args": []},
        {"name": "f64.min", "opcode": 0xa4, "description": "", "feature": 0, "args": []},
        {"name": "f64.max", "opcode": 0xa5, "description": "", "feature": 0, "args": []},
        {"name": "f64.copysign", "opcode": 0xa6, "description": "", "feature": 0, "args": []},

        # # Conversions
        {"name": "i32.wrap/i64", "opcode": 0xa7, "description": "", "feature": 0, "args": []},
        {"name": "i32.trunc_s/f32", "opcode": 0xa8, "description": "", "feature": 0, "args": []},
        {"name": "i32.trunc_u/f32", "opcode": 0xa9, "description": "", "feature": 0, "args": []},
        {"name": "i32.trunc_s/f64", "opcode": 0xaa, "description": "", "feature": 0, "args": []},
        {"name": "i32.trunc_u/f64", "opcode": 0xab, "description": "", "feature": 0, "args": []},
        {"name": "i64.extend_s/i32", "opcode": 0xac, "description": "", "feature": 0, "args": []},
        {"name": "i64.extend_u/i32", "opcode": 0xad, "description": "", "feature": 0, "args": []},
        {"name": "i64.trunc_s/f32", "opcode": 0xae, "description": "", "feature": 0, "args": []},
        {"name": "i64.trunc_u/f32", "opcode": 0xaf, "description": "", "feature": 0, "args": []},
        {"name": "i64.trunc_s/f64", "opcode": 0xb0, "description": "", "feature": 0, "args": []},
        {"name": "i64.trunc_u/f64", "opcode": 0xb1, "description": "", "feature": 0, "args": []},
        {"name": "f32.convert_s/i32", "opcode": 0xb2, "description": "", "feature": 0, "args": []},
        {"name": "f32.convert_u/i32", "opcode": 0xb3, "description": "", "feature": 0, "args": []},
        {"name": "f32.convert_s/i64", "opcode": 0xb4, "description": "", "feature": 0, "args": []},
        {"name": "f32.convert_u/i64", "opcode": 0xb5, "description": "", "feature": 0, "args": []},
        {"name": "f32.demote/f64", "opcode": 0xb6, "description": "", "feature": 0, "args": []},
        {"name": "f64.convert_s/i32", "opcode": 0xb7, "description": "", "feature": 0, "args": []},
        {"name": "f64.convert_u/i32", "opcode": 0xb8, "description": "", "feature": 0, "args": []},
        {"name": "f64.convert_s/i64", "opcode": 0xb9, "description": "", "feature": 0, "args": []},
        {"name": "f64.convert_u/i64", "opcode": 0xba, "description": "", "feature": 0, "args": []},
        {"name": "f64.promote/f32", "opcode": 0xbb, "description": "", "feature": 0, "args": []},

        # Reinterpretations
        {"name": "i32.reinterpret/f32", "opcode": 0xbc, "description": "",  "feature": 0, "args": []},
        {"name": "i64.reinterpret/f64", "opcode": 0xbd, "description": "",  "feature": 0, "args": []},
        {"name": "f32.reinterpret/i32", "opcode": 0xbe, "description": "",  "feature": 0, "args": []},
        {"name": "f64.reinterpret/i64", "opcode": 0xbf, "description": "",  "feature": 0, "args": []},

    ]

    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self.PTRSZ = 4
        self.init_instructions()
        self.init_registers()
        return


    #
    # Processor callback section
    #

    def notify_get_autocmt(self, insn):
        for name, itype in self.inames.iteritems():
            if itype == insn.itype:
                for wi in self.insns:
                    if wi.name == name:
                        return wi.description


    def notify_emu(self, insn):
        dbg("in notify_emu...")
        aux = insn.auxpref
        ft = insn.get_canon_feature()

        if ft & CF_STOP == 0:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
        if ft & CF_JUMP:
            if self.insns[insn.itype].name == "if":
                nb = 0
                while True:
                    cur = insn.get_next_byte()
                    nb += 1
                    if cur in (0x05, 0x0b): # `end` or `else`
                        break
                nb += 1
                insn.size -= nb
                add_cref(insn.ea, insn.ea + nb, fl_JN)
            else:
                remember_problem(PR_JUMP, insn.ea)
        return 1


    def notify_out_operand(self, ctx, op):
        dbg("in notify_out_operand...")
        optype = op.type
        fl = op.specval
        signed = OOF_SIGNED if fl & FL_SIGNED else 0
        ctx.out_value(op, OOFW_IMM | signed | (OOFW_32 if self.PTRSZ == 4 else OOFW_64))
        return True


    def notify_out_insn(self, ctx):
        dbg("in notify_out_insn...")
        operands = []

        ctx.out_mnemonic()
        for i in range(UA_MAXOP):
            op = ctx.insn[i]
            if op.type == o_void: break
            operands.append(op)

        for i, op in enumerate(operands):
            ctx.out_char(' ')
            ctx.out_one_operand(i)
            if i != len(operands)-1:
                ctx.out_symbol(',')

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return


    def notify_ana(self, insn):
        dbg("in notify_ana...")
        self._ana(insn)
        return insn.size


    def ev_out_operand(self, ctx, op):
        dbg("in ev_out_operand...")
        return 1


    def ev_out_insn(self, ctx):
        dbg("in ev_out_insn...")
        return



    #
    # Processor initialization
    #


    def init_instructions(self):
        dbg("Initializing WASM processor instruction set...")
        self.inames = {}
        self.insns = {}
        WasmInstruction = collections.namedtuple("WasmInstruction", ["name" , "opcode" , "description" , "feature", "args"])
        for i, ins in enumerate(self.instrs):
            wi = WasmInstruction(**ins)
            self.inames[wi.name] = i
            self.insns[wi.opcode] = wi
        return



    def init_registers(self):
        self.regs_num = 1
        self.reg_names = ["r%d" % d for d in range(0, self.regs_num)]
        self.reg_names+= ["CS", "DS"]
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i

        self.reg_first_sreg = self.reg_code_sreg = self.reg_ids["CS"]
        self.reg_last_sreg  = self.reg_data_sreg = self.reg_ids["DS"]
        return



    #
    # Analysis and decoding functions
    #

    def _ana(self, insn):
        dbg("_ana at 0x%x" % insn.ea)
        opcode = insn.get_next_byte()

        if not opcode in self.insns:
            raise DecodingError("Unknown opcode 0x%x at offset 0x%x" % (opcode, insn.ea))

        wi = self.insns[opcode]

        insn.itype = self.inames[wi.name]
        insn.size = 1

        dbg("creating insn %s (type=%d, size=%d, ea=%x, ip=%x)" % (wi.name, insn.itype, insn.size, insn.ea, insn.ip))

        if wi.args:

            for i, arg_t in enumerate(wi.args):
                op = insn.ops[i]

                if arg_t is varuint32:
                    raw_bytes = get_next_bytes(insn, 4)
                    arg = varuint32(raw_bytes)
                    op.type = o_imm
                    op.value = arg.value
                    op.flags = OF_SHOW
                    op.specval |= FL_SIGNED
                    op.addr = insn.ea + insn.size
                    insn.size += arg.size
                    dbg("adding VARUINT32 operand (value=%d, size=%d, raw=%s)" % (arg.value, arg.size, repr(raw_bytes)))
                    continue

                if arg_t is block_type:
                    raw_bytes = get_next_bytes(insn, 4)
                    b = block_type(raw_bytes)
                    op.type = o_imm
                    op.value = b.value
                    op.flags = OF_SHOW
                    op.specval |= FL_SIGNED
                    op.addr = insn.ea + insn.size
                    insn.size += b.size
                    dbg("adding BLOCK_TYPE operand (value=%d, size=%d, raw=%s)" % (b.value, b.size, repr(raw_bytes)))
                    continue

                if arg_t is memory_immediate:
                    raw_bytes = get_next_bytes(insn, 8)
                    mi = memory_immediate(raw_bytes)
                    op.type = o_imm
                    op.value = mi.flags
                    op.flags = OF_SHOW
                    op.specval |= FL_SIGNED
                    op.addr = insn.ea + insn.size
                    insn.size += mi.size
                    dbg("adding MEMORY_IMMEDIATE operand (value=%d, size=%d, raw=%s)" % (mi.value, mi.size, repr(raw_bytes)))
                    continue

                # default
                op.type = o_void
                op.flags = 0

        dbg("opcode %x -> %s, size=%d" % (wi.opcode, wi.name, insn.size))
        return insn.size


def PROCESSOR_ENTRY():
    return wasm_processor_t()
