import os
import sys
import pydffi

class Instr:
    def __init__(self, addr, txt, raw):
        self.addr = addr
        self.txt = txt
        self.raw = raw
    def __repr__(self):
        return "%08X: %s" % (self.addr,b"\t".join(self.txt).decode("ascii"))

class LLVMDisasm:
    def __init__(self, llvm_root):
        pydffi.dlopen(os.path.join(llvm_root, "lib", "libLLVM.so"))
        self.FFI=pydffi.FFI(includeDirs=[os.path.join(llvm_root, "include")])
        self.CU=self.FFI.cdef('''
        #include <llvm-c/Target.h>
        #include <llvm-c/Disassembler.h>

        size_t disasm(LLVMDisasmContextRef Disasm, uint8_t const* In, size_t InLen, uint64_t Addr, char* Out, size_t OutLen)
        {
          return LLVMDisasmInstruction(Disasm, (uint8_t*)In, InLen, Addr, Out, OutLen);
        }
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
        self.LLVMDisasmInstruction = self.CU.funcs.disasm
        self.tmpbuf = self.FFI.arrayType(self.FFI.CharTy, 256)()

    def __del__(self):
        self.CU.funcs.LLVMDisasmDispose(self.llvm_disasm)

    def disasm(self, data, addr):
        size = int(self.LLVMDisasmInstruction(self.llvm_disasm,
            data, len(data), addr,
            self.tmpbuf, len(self.tmpbuf)))
        txt = bytes(self.tmpbuf).lstrip(b"\t")
        txt = txt[:txt.index(b"\x00")]
        return txt.split(b"\t"), size

    def disasm_func(self, data, addr):
        view = memoryview(data)
        while len(view) > 0:
            txt, instsize = self.disasm(view, addr)
            if instsize == 0:
                break
            yield Instr(addr, txt, bytes(data[:instsize]))
            addr += instsize
            view = view[instsize:]

    def disasm_binary(self, lief_bin):
        for f in lief_bin.functions:
            data = lief_bin.get_content_from_virtual_address(f.address, f.size)
            yield from self.disasm_func(bytes(data), f.address)

if __name__ == "__main__":
    import sys
    import lief
    llvm_root, Bin = sys.argv[1:]
    Bin = lief.parse(Bin)
    D = LLVMDisasm(llvm_root)
    for inst in D.disasm_binary(Bin):
        print(inst.txt)
