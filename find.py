import sys
import copy
import lief
import random
from miasm.expression.expression import ExprId, ExprInt

from llvm_disasm import LLVMDisasm
from miasm_emu import regs as miasm_regs
from miasm_emu import sym as miasm_sym
from analyze_table import extract_table, analyze_table, ASCII_START

if len(sys.argv) < 4:
    print("Usage: %s llvm_root libc ninstrs" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

llvm_root, libc_path, ninstrs = sys.argv[1:]
ninstrs = int(ninstrs)

Bin = lief.parse(libc_path)

# Find all indirect calls/jumps, and save all instructions
print("[x] Disassembling...")
D = LLVMDisasm(llvm_root)
all_instrs = []
ends = []
for inst in D.disasm_binary(Bin):
    all_instrs.append(inst)
    # Fast'n'dirty
    if inst.txt[0] in (b"call",b"jmp") and inst.txt[1].startswith(b"r"):
        ends.append(len(all_instrs)-1)

# Then, for each jump/call, symbolically execute starting N instructions before with
# Miasm, and check if we have what we want.
BLACKLIST = [b"ret",b"syscall",b"jz",b"jnz",b"je",b"ja",b"jne",b"jbe",b"retf",b"int3",b"iretd",b"jg",b"leave",b"enter",b"jp",b"jo",b"int",b"hlt",b"jge",b"jb",b"jae",b"int1",b"call",b"jmp",b"js"]
def is_blacklisted(instr):
    return instr.txt[0] in BLACKLIST

def get_gadget(all_instrs, idx, ninstrs):
    gadget = [all_instrs[idx]]
    idx -= 1
    while len(gadget) < ninstrs:
        if idx < 0:
            break
        instr = all_instrs[idx]
        if is_blacklisted(instr):
            break
        gadget.append(instr)
        idx -= 1
    return list(reversed(gadget)) if len(gadget) > 1 else None

def emulate(bin_, gadget, status):
    first,last = gadget[0],gadget[-1]
    data = bytes(bin_.get_content_from_virtual_address(first.addr,last.addr-first.addr+len(last.raw)))
    return miasm_sym(data, first.addr, status)

def filter_(IRDst, in_):
    if IRDst == in_:
        return False, None
    if any(rinit in IRDst for rinit in miasm_regs.regs_init.values()):
        return False
    return in_ in IRDst


# Symbolic input status, dependig on the indirect function we target.
# stauts0 is for _xor, status1 is for _or
in_ = ExprId("in", 64)
status0 = {miasm_regs.RDI: in_}
status1 = {miasm_regs.RSI: in_, miasm_regs.RAX: in_, miasm_regs.RBX: ExprInt(0,64)}

def compute_rel_addresses(table, idxes, table_addr):
    # Returns {address: character}
    return {(table_addr + table[i]) & 0xFFFFFFFFFFFFFFFF: chr(ASCII_START+i) for i in idxes}

# We define a maximum value for the offset in jump tables. Indeed, the address
# we speculitabely jump to still needs to be mapped in memory. We could be more
# precise, and compute this relative to the jump table address.
JPT_MAX_VAL = 1024*1024 + 500*1024 # 1.5Mb

print("[x] Found %d indirect calls/jmps. Looking for valid gadgets..." % len(ends))
for e in ends:
    gadget = get_gadget(all_instrs, e, ninstrs)
    if gadget is None: continue
    addr = gadget[0].addr
    for status in (status0, status1):
        IRDst = emulate(Bin, gadget, status)
        if IRDst is None:
            print("[-] Warning: enable to emulate gadget at 0x%08X" % addr)
            continue
        if not filter_(IRDst, in_): continue
        ext_table = extract_table(Bin, IRDst, in_)
        if ext_table is None: continue
        table, table_addr, table_elt_size = ext_table
        idxes = analyze_table(table, 256, JPT_MAX_VAL)
        if len(idxes) > 0:
            chars = ''.join(chr(ASCII_START+i) for i in sorted(idxes))
            # Randomize the table and the address to "measure" at
            #char_addrs = "{ %s }" % ",".join("{ %s, '%s' }" % (hex(addr), char) for addr,char in randitems)
            #rel_addrs = compute_rel_addresses(table, idxes, table_addr)
            #randitems = list(rel_addrs.items())
            #random.shuffle(randitems)
            #print("(+] Gadget at %s, table with %d elts, valid characters: '%s', addresses: %s" % (hex(addr), len(idxes), chars, char_addrs))
            print("[+] Gadget at %s, table with %d elts, table address = 0x%08X, element size = %d, valid characters: '%s'" % (hex(addr), len(idxes), table_addr, table_elt_size, chars))
