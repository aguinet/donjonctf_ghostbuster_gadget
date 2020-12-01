import copy
import miasm.expression.expression
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core import parse_asm, asmblock
from miasm.arch.x86.sem import ir_x86_32 as ir_32, ir_x86_64 as ir_64
from miasm.expression.expression import ExprMem, ExprId, ExprInt, ExprAssign, ExprCond, ExprSlice, ExprOp
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators import Translator
from miasm.arch.x86 import regs as x86_regs
from miasm.expression.simplifications import expr_simp_explicit, expr_simp
from miasm.core.locationdb import LocationDB

machine = Machine("x86_64")
loc_db = LocationDB()
ira = machine.ira(loc_db)
regs = ira.arch.regs

def sym(data, addr, status):
    cont = Container.from_string(data, loc_db = loc_db, addr=addr)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
    asm_block = mdis.dis_block(addr)

    # Translate ASM -> IR
    ircfg = ira.new_ircfg()
    try:
        ira.add_asmblock_to_ircfg(asm_block, ircfg)
    except NotImplementedError:
        return None

    # Instantiate a Symbolic Execution engine with default value for registers
    regs_init = regs.regs_init
    sympool = copy.deepcopy(regs_init)
    sympool.update(status)
    symb = SymbolicExecutionEngine(ira, sympool)

    # Emulate one IR basic block
    ## Emulation of several basic blocks can be done through .emul_ir_blocks
    cur_addr = symb.run_at(ircfg, addr)
    IRDst = symb.symbols[ira.IRDst]

    expr = expr_simp_explicit(IRDst)
    #if isinstance(expr, ExprMem):
    #    expr = expr.ptr
    return expr

if __name__ == "__main__":
    # add     rdx, 40h ; '@'
    # add     rsi, rdx
    # add     rdi, rdx
    # lea     r11, jpt_191892
    # movsxd  rcx, ds:(jpt_191892 - 1BCFE0h)[r11+rdx*4] ; switch 80 cases
    # add     rcx, r11
    # jmp     rcx
    data = bytes.fromhex("4883C2404801D64801D74C8D1D06AD020049630C934C01D9FFE1")
    IRDst = sym(data, 0x1922C9)
    print(IRDst)
    print(expr_contains((regs.RAX,), IRDst))
