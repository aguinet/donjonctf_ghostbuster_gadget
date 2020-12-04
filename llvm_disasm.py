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

TMPBUF_SIZE = 256

class LLVMDisasm:
    def __init__(self, llvm_root):
        pydffi.dlopen(os.path.join(llvm_root, "lib", "libLLVM.so"))
        self.FFI=pydffi.FFI(includeDirs=[os.path.join(llvm_root, "include")],optLevel=2)
        self.CU=self.FFI.cdef('''
        #include <llvm-c/Target.h>
        #include <llvm-c/Disassembler.h>
        ''')
        self.CU2=self.FFI.compile('''
#include <llvm-c/Target.h>
#include <llvm-c/Disassembler.h>
#include <stddef.h>

size_t disasm(LLVMDisasmContextRef Disasm,
    uint8_t const* In, size_t InLen, uint64_t Addr,
    char* Out, size_t OutLen)
{
  return LLVMDisasmInstruction(Disasm, (uint8_t*)In, InLen, Addr, Out, OutLen);
}

typedef struct {
  char Buf[256];
  uint64_t Addr;
  size_t Len;
} Instr;

size_t disasm_instrs(LLVMDisasmContextRef Disasm,
    uint8_t const* In, size_t InLen, uint64_t Addr,
    Instr* Outs, size_t NOut, uint64_t* pSize)
{
  size_t I = 0;
  size_t SumLen = 0;
  for (; I < NOut; ++I) {
    Instr* OI = &Outs[I];
    size_t Len = LLVMDisasmInstruction(Disasm,
      (uint8_t*)In, InLen, Addr,
      OI->Buf, sizeof(OI->Buf));
    if (Len == 0) {
      break;
    }
    SumLen += Len;
    OI->Len = Len;
    OI->Addr = Addr;
    In += Len;
    Addr += Len;
  }
  if (pSize) *pSize = SumLen;
  return I;
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
        self.LLVMDisasmInstruction = self.CU2.funcs.disasm
        self.cdisasm_instrs = self.CU2.funcs.disasm_instrs
        self.tmpbuf = (self.FFI.arrayType(self.FFI.CharTy, TMPBUF_SIZE))()
        self.tmpinstrs = self.FFI.arrayType(self.CU2.types.Instr, 10)()

    def __del__(self):
        self.CU.funcs.LLVMDisasmDispose(self.llvm_disasm)

    def _process_instr(self, buf):
        txt = bytes(buf).lstrip(b"\t")
        txt = txt[:txt.index(b"\x00")]
        return txt.split(b"\t")

    def disasm(self, data, addr):
        size = int(self.LLVMDisasmInstruction(self.llvm_disasm,
            data, len(data), addr,
            self.tmpbuf, len(self.tmpbuf)))
        return self._process_instr(self.tmpbuf), size

    def disasm_instrs(self, data, addr):
        size = self.FFI.UInt64(0)
        n = int(self.cdisasm_instrs(self.llvm_disasm,
            data, len(data), addr,
            self.tmpinstrs, len(self.tmpinstrs), 
            pydffi.ptr(size)))
        instrs = (self.tmpinstrs[i] for i in range(n))
        instrs = (Instr(I.Addr, self._process_instr(I.Buf), b"") for I in instrs)
        return instrs, int(size)

    def disasm_func(self, data, addr):
        view = memoryview(data)
        while len(view) > 0:
            instrs, instrsize = self.disasm_instrs(view, addr)
            if instrsize == 0:
                break
            yield from instrs
            addr += instrsize
            view = view[instrsize:]

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
