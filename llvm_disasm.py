import os
import sys
import pydffi

class Instr:
    def __init__(self, addr, txt, raw):
        self.addr = addr
        self.txt = txt
        self.raw = raw
    def __repr__(self):
        return "%08X: %s" % (self.addr,self.txt)

class LLVMDisasm:
    def __init__(self, llvm_root):
        pydffi.dlopen(os.path.join(llvm_root, "lib", "libLLVM.so"))
        self.FFI=pydffi.FFI(includeDirs=[os.path.join(llvm_root, "include")])
        self.CU=self.FFI.cdef('''
        #include <string.h>
        #include <llvm-c/Target.h>
        #include <llvm-c/Disassembler.h>
        ''')
        self.CU.funcs.LLVMInitializeX86Disassembler()
        self.CU.funcs.LLVMInitializeX86Target()
        self.CU.funcs.LLVMInitializeX86TargetInfo()
        self.CU.funcs.LLVMInitializeX86TargetMC()
        self.llvm_disasm = self.CU.funcs.LLVMCreateDisasm("x86_64-pc-linux-gnu",
            (self.FFI.VoidPtrTy)(), self.FFI.Int(0), (self.FFI.VoidPtrTy)(), (self.FFI.VoidPtrTy)())
        if int(self.llvm_disasm) == 0:
            raise RuntimeError("unable to create an LLVM disassembler engine")
        # Set Intel syntax
        self.CU.funcs.LLVMSetDisasmOptions(self.llvm_disasm, 4)
        self.LLVMDisasmInstruction = self.CU.funcs.LLVMDisasmInstruction
        self.strlen = self.CU.funcs.strlen
        self.tmpbuf = self.FFI.arrayType(self.FFI.CharTy, 256)()

    def __del__(self):
        self.CU.funcs.LLVMDisasmDispose(self.llvm_disasm)

    def disasm(self, data, addr):
        size = self.LLVMDisasmInstruction(self.llvm_disasm, bytearray(data), len(data), addr, self.tmpbuf, len(self.tmpbuf)).value
        outlen = self.strlen(self.tmpbuf).value
        txt = bytes(self.tmpbuf)[:outlen].strip()
        return txt.split(b"\t"), size

    def disasm_func(self, data, addr):
        while True:
            txt, instsize = self.disasm(data, addr)
            if instsize == 0:
                break
            yield Instr(addr, txt, data[:instsize])
            addr += instsize
            data = data[instsize:]

    def disasm_binary(self, lief_bin):
        for f in lief_bin.functions:
            yield from self.disasm_func(lief_bin.get_content_from_virtual_address(f.address, f.size), f.address)
