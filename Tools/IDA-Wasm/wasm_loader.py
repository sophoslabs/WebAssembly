# -*- mode: python -*-
# -*- coding: utf-8 -*-
#
# WebAssembly loader for IDA Pro 7.+
#
#
# To install, simply copy `wasm_loader.py` in :
#  - C:\Program Files\IDA 7.1\loaders  (system-wide)
#  - %APPDATA%\Hex Rays\IDA\loaders  (user only)
#

import idc, idaapi
from idaapi import *
from idc import *

import struct

DEBUG = True


def enum(**enums):
    return type('Enum', (), enums)

def u8 (x): return struct.unpack("<B", x)[0]
def u16(x): return struct.unpack("<H", x)[0]
def u32(x): return struct.unpack("<I", x)[0]
def u64(x): return struct.unpack("<Q", x)[0]

def p8 (x): return struct.pack("<B", x)
def p16(x): return struct.pack("<H", x)
def p32(x): return struct.pack("<I", x)
def p64(x): return struct.pack("<Q", x)

class DecodingError(Exception): pass

class uint32:
    def __init__(self, raw):
        self.raw = raw[:4]
        self.value = u32(self.raw)
        self.max_size = self.size = 4


class uint64:
    def __init__(self, raw):
        self.raw = raw[:8]
        self.value = u64(self.raw)
        self.max_size = self.size = 8


class varuint32:
    max_size = 4
    def __init__(self, raw):
        self.raw = raw
        self.size, self.value = varint_decode_bytes(self.raw)


class varuint64(varuint32):
    max_size = 8

class func_type:
    def __init__(self, fd):
        _, self.form = varint_decode_stream(fd)
        _, self.param_count = varint_decode_stream(fd)
        self.param_types = []
        for i in range(self.param_count):
            _, self.param_types.append(varint_decode_stream(fd)[1])
        _, self.return_count = varint_decode_stream(fd)
        if self.return_count == 1:
            _, self.return_type = varint_decode_stream(fd)

class global_type:
    def __init__(self, fd):
        _, self.content_type = varint_decode_stream(fd)
        self.mutability = read_one(fd)

class table_type:
    def __init__(self, fd):
        _, self.element_type = varint_decode_stream(fd)
        self.limits = resizable_limits(fd)

class memory_type:
    def __init__(self, fd):
        self.limits = resizable_limits(fd)

class resizable_limits:
    def __init__(self, fd):
        _, self.flags = varint_decode_stream(fd)
        _, self.initial = varint_decode_stream(fd)
        _, self.maximal = varint_decode_stream(fd)

def read_one(stream):
    c = stream.read(1)
    if c == '':
        raise EOFError("Unexpected EOF while reading bytes")
    return ord(c)

def read_n(stream, n):
    res = []
    while n:
        c = stream.read(1)
        if c == '':
            break
        res.append(c)
        n -= 1
    return res

def read_until(stream, c):
    res = []
    while True:
        cur = read_one(stream)
        res.append(cur)
        if cur == c:
            break
    return res


# From https://github.com/fmoo/python-varint/blob/master/varint.py
def varint_decode_stream(stream):
    shift = 0
    result = 0
    j = 0
    while True:
        i = read_one(stream)
        result |= (i & 0x7f) << shift
        shift += 7
        j += 1
        if not (i & 0x80):
            break
    return j, result


def varint_decode_bytes(buf):
    return varint_decode_stream(io.BytesIO(buf))


def AddWasmSegment(startea, endea, name, cls=None, base=0):
    s = segment_t()
    s.start_ea = startea
    s.end_ea = endea
    s.sel = setup_selector(base)
    s.use32 = 0
    s.align = saRelByte # saRelDble
    s.perm = SEGPERM_EXEC | SEGPERM_WRITE | SEGPERM_READ
    fl = ADDSEG_OR_DIE
    idaapi.add_segm_ex(s, name, cls, fl)
    return


class WasmSection:
    id = None            # varuint7
    payload_len = None   # varuint32
    name_len = None      # varuint32
    bytes = None
    payload_data = None
    start_ea = 0
    end_ea = 0

    CUSTOM=0
    TYPE=1
    IMPORT=2
    FUNCTION=3
    TABLE=4
    MEMORY=5
    GLOBAL=6
    EXPORT=7
    START=8
    ELEMENT=9
    CODE=10
    DATA=11

    @staticmethod
    def id_str(i):
        if i==0: return "CUSTOM"
        if i==1: return "TYPE"
        if i==2: return "IMPORT"
        if i==3: return "FUNCTION"
        if i==4: return "TABLE"
        if i==5: return "MEMORY"
        if i==6: return "GLOBAL"
        if i==7: return "EXPORT"
        if i==8: return "START"
        if i==9: return "ELEMENT"
        if i==10: return "CODE"
        if i==11: return "DATA"


value_type = enum(i32=0x7f, i64=0x7e, f32=0x7d, f64=0x7c)


class LocalEntry:
    count = 0 # varuint32
    type = 0 # value_type (varint7)


class FunctionBody:
    body_size = 0 # varuint32
    local_count = 0 # varuint32
    locals = []
    code = []
    end = 0x0b
    start_ea = 0
    end_ea = 0
    ordinal = 0


class CodeSection:
    count = 0 # variunt32
    function_bodies = [] # array of FunctionBody


class ElemSegment:
    index = 0
    offset = None
    num_elem = 0
    elems = []


class ElementSection:
    count = 0 # variunt32
    entries = []


class ImportSection:
    count = 0 # variunt32
    entries = []


class ImportEntry:
    module_len = 0 # variunt32
    module_str = None
    field_len = 0 # variunt32
    field_str = None
    kind = 0
    module_str_addr = 0
    field_str_addr = 0
    type = 0


class ExportSection:
    count = 0 # variunt32
    entries = []


class ExportEntry:
    field_len = 0 # variunt32
    field_str = None
    kind = 0
    index = 0
    start_ea = 0
    end_ea = 0



class WASM:
    MAGIC = "\x00asm"
    VERSION = 1

    def __init__(self, fd, *args, **kwargs):
        fd.seek(0)
        raw = fd.read(8)
        header, version = raw[:4], u32(raw[4:8])
        assert header == WASM.MAGIC and version == WASM.VERSION
        self.sections = []
        self.code_start = None
        self.entry_point = None
        self.code_end = None
        self.fd = fd
        return


    def __parse_code_section(self, fd):
        cs = CodeSection()
        _, cs.count = varint_decode_stream(fd)
        for i in range(cs.count):
            fb = FunctionBody()
            _, fb.body_size = varint_decode_stream(fd)
            _, fb.local_count = varint_decode_stream(fd)
            local_start = fd.tell()
            for j in range(fb.local_count):
                le = LocalEntry()
                _, le.count = varint_decode_stream(fd)
                _, le.type = varint_decode_stream(fd)
                fb.locals.append(le)
            fb.start_ea = fd.tell()
            if DEBUG: print(fb.start_ea - local_start)
            fb.code = fd.read(fb.body_size - (fb.start_ea - local_start) - 1)
            end = u8(fb.code[-1])
            fb.end_ea = fd.tell()
            if DEBUG: print("FunctionBody {:x}-{:x} , body_size={:x}, local_count={:x}".format(fb.start_ea, fb.end_ea, fb.body_size, fb.local_count))
            assert end == FunctionBody.end, "[CODE] {:x} != {:x} at {:x}".format(end, FunctionBody.end, fb.end_ea)
            fb.ordinal = i
            cs.function_bodies.append(fb)
        return cs


    def __parse_element_section(self, fd):
        es = ElementSection()
        _, es.count = varint_decode_stream(fd)
        for i in range(es.count):
            e = ElemSegment()
            _, e.index = varint_decode_stream(fd)
            e.offset = read_until(fd, 0x0b) # varint_decode_stream(fd)
            _, e.num_elem = varint_decode_stream(fd)
            for j in range(e.num_elem):
                _, elem = varint_decode_stream(fd)
                e.elems.append(elem)
        return es


    def __parse_import_section(self, fd):
        imp = ImportSection()
        _, imp.count = varint_decode_stream(fd)
        for ent in range(imp.count):
            # print("%d - %#x" % (ent, fd.tell()))
            ie = ImportEntry()
            _, ie.module_len = varint_decode_stream(fd)
            ie.module_str_addr = fd.tell()
            ie.module_str = fd.read(ie.module_len)
            _, ie.field_len = varint_decode_stream(fd)
            ie.field_str_addr = fd.tell()
            ie.field_str = fd.read(ie.field_len)
            ie.kind = read_one(fd)
            if ie.kind == 0:                ie.type = varint_decode_stream(fd)
            elif ie.kind == 1:              ie.type = table_type(fd)
            elif ie.kind == 2:              ie.type = memory_type(fd)
            elif ie.kind == 3:              ie.type = global_type(fd)
            imp.entries.append(ie)
        return imp


    def __parse_export_section(self, fd):
        exp = ExportSection()
        _, exp.count = varint_decode_stream(fd)
        for ent in range(exp.count):
            ee = ExportEntry()
            _, ee.field_len = varint_decode_stream(fd)
            ee.start_ea = fd.tell()
            ee.field_str = fd.read(ee.field_len)
            ee.end_ea = fd.tell()
            ee.kind = read_one(fd)
            _, ee.index = varint_decode_stream(fd)
            exp.entries.append(ee)
        return exp


    def parse(self):
        fd = self.fd
        fd.seek(8)

        fd.file2base(0, 0, 8, False)
        AddWasmSegment(0, 8, "HEADER")

        while True:
            try:
                s = WasmSection()
                s.start_ea = fd.tell()
                _, s.id = varint_decode_stream(fd)
                assert s.id in range(12), "[parser] Found invalid id %d at %#x" % (s.id, s.start_ea)
                _, s.payload_len = varint_decode_stream(fd)
                if DEBUG: print("{:d} - {:s}".format(s.id, WasmSection.id_str(s.id)))

                if s.id == WasmSection.CUSTOM:
                    sizeof_namelen, s.name_len = varint_decode_stream(fd)
                    s.name = fd.read(s.name_len)
                    s.payload_data = fd.read(s.payload_len - len(s.name) - sizeof_namelen)

                elif s.id == WasmSection.CODE:
                    s.payload_data = self.__parse_code_section(fd)

                elif s.id == WasmSection.ELEMENT:
                    s.payload_data = self.__parse_element_section(fd)

                elif s.id == WasmSection.IMPORT:
                    s.payload_data = self.__parse_import_section(fd)

                elif s.id == WasmSection.EXPORT:
                    s.payload_data = self.__parse_export_section(fd)

                else:
                    s.payload_data = fd.read(s.payload_len)

                s.end_ea = fd.tell()
                self.sections.append(s)
            except Exception as e:
                print("[!] Raised exception '%s'" % str(e))
                break

        for s in self.sections:
            name = WasmSection.id_str(s.id)
            print ("[+] Adding new Section '%s': %x-%x" % (name, s.start_ea, s.end_ea))
            fd.file2base(s.start_ea, s.start_ea, s.end_ea, True)
            cls=""

            if s.id == WasmSection.CODE:
                self.code_start = s.start_ea
                self.code_end  = s.end_ea
                for fb in s.payload_data.function_bodies:
                    add_entry(fb.start_ea, fb.start_ea, "sub_{:08x}".format(fb.start_ea), 1)

                cls = "CODE"

            if s.id == WasmSection.EXPORT:
                for idx, ee in enumerate(s.payload_data.entries):
                    if DEBUG: print("[EXPORT] Making str %d at %x (len=%x)" % (idx, ee.start_ea, ee.field_len))
                    idc.MakeStr(ee.start_ea,  ee.start_ea+ee.field_len)

            if s.id == WasmSection.IMPORT:
                for idx, imp in enumerate(s.payload_data.entries):
                    # if DEBUG: print("[IMPORT] Making module str %d at %x (len=%x)" % (idx, imp.module_str_addr, imp.module_len))
                    # idc.MakeStr(imp.module_str_addr, imp.module_str_addr+imp.module_len)
                    # if DEBUG: print("[IMPORT] Making field str %d at %x (len=%x)" % (idx, imp.field_str_addr, imp.field_len))
                    # idc.MakeStr(imp.field_str_addr, imp.field_str_addr+imp.field_len)
                    __class = idaapi.get_many_bytes(imp.module_str_addr, imp.module_len)
                    __func = idaapi.get_many_bytes(imp.field_str_addr, imp.field_len)
                    MakeDword(imp.module_str_addr)
                    MakeName(imp.module_str_addr, "%s::%s" % (__class, __func))

                cls = "XTRN"

                # TODO add entry in Modules tab

            AddWasmSegment(s.start_ea, s.end_ea, name, cls)

        return


def accept_file(f, n):
    size = f.size()
    retcode = 0
    magic = f.read(4)
    if magic == WASM.MAGIC:
        ver = u32(f.read(4))
        if ver == WASM.VERSION:
            retcode = {"format": "WASM v%d Image" % ver , "processor":"wasm"}
    return retcode


def load_file(f, neflags, fmt):
    SetProcessorType("wasm", SETPROC_ALL)
    WASM(f).parse()
    return 1
