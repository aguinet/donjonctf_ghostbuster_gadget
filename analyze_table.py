import itertools
import ctypes
import struct
from miasm.expression.expression import ExprMem, ExprId, ExprInt, ExprAssign, ExprCond, ExprSlice, ExprOp, ExprWalk

ASCII_START = 32
ASCII_END = 127
fmts_ = {2: "H", 4: "I", 8: "Q"}
cts = {2: ctypes.c_int16, 4: ctypes.c_int32, 8: ctypes.c_int64}

def analyze_table(table, min_diff_val, max_val):
    stable = sorted(table)
    min_diff = min(abs(stable[i]-stable[i+1]) for i in range(len(stable)-1))
    idxes = list(range(len(table)))
    if min_diff >= min_diff_val:
        print("[X] FOUND PERFECT TABLE, min_diff is %d", min_diff)
        return idxes
    idxes = sorted(idxes, key=lambda v: table[v])
    ret = []

    idx0,idx1 = idxes[0],idxes[1]
    v0,v1 = table[idx0],table[idx1]
    if abs(v1-v0) >= min_diff_val: ret.append(idx0)
    for i in range(1,len(idxes)-1):
        idxm1,idx0,idx1 = idxes[i-1],idxes[i],idxes[i+1]
        vm1,v0,v1 = table[idxm1],table[idx0],table[idx1]
        if abs(v1-v0) >= min_diff_val and abs(vm1-v0) >= min_diff_val:
            ret.append(idx0)

    ret = [i for i in ret if table[i] <= max_val]
    if len(ret) == 0:
        return ret
    if len(ret) == 1:
        v0 = table[ret[0]]
        assert(table.count(v0) == 1)
        assert(min(abs(v-v0) for v in table if v != v0) >= min_diff_val)
    else:
        final_min = min(abs(table[a]-table[b]) for a,b in itertools.combinations(ret, 2))
        assert(final_min >= min_diff_val)
    return ret

def expr_get_table_ptr(expr, in_):
    # search for in*cst0 + cst1
    if not (isinstance(expr, ExprOp) and expr.op == "+"):
        return None
    a,b = expr.args
    if not isinstance(b, ExprInt):
        return None
    if not (isinstance(a, ExprOp) and a.op == "*"):
        return None
    a0 = a.args[0]
    if in_ in a0: 
        mulby = a.args[1]
        assert(isinstance(mulby, ExprInt))
        return b.arg, mulby.arg
    return None

def extract_table(binary, expr, in_):
    table = ExprWalk(lambda e: expr_get_table_ptr(e,in_)).visit(expr)
    if table is None:
        return None
    addr, mulby = table
    data = bytes(binary.get_content_from_virtual_address(addr+ASCII_START*mulby, (ASCII_END-ASCII_START)*mulby))
    # TODO: hard-coded endianess (can be gathered from the binary)
    fmt = "<"+fmts_[mulby]
    data = [struct.unpack(fmt, data[i:i+mulby])[0] for i in range(0, len(data), mulby)]
    # We consider that offsets are all signed integers (altought this could be
    # extracted from the Miasm expression). We thus convert values into
    # properly Python signed integers using ctypes.
    cty = cts[mulby]
    data = [cty(v).value for v in data]
    return data, addr, mulby

if __name__ == "__main__":
    #table=[-814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -814156, -815022, -814981, -813204, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813100, -813204, -813188, -813188, -813188, -813252, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813308, -813204, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813188, -813796, -813908, -806740, -806451, -806451, -806451, -806451, -806451, -806451, -806451, -806451, -807145, -807104, -806451, -806451, -806451, -806451]
    table = [-999780, -999529, -999780, -999515, -999522, -999501, -999508, -999543, -999494, 0, 0, 0, 0, 0, 0, 0, 2098182, 8192, 2098184, 16384, 2098185, 32768, 52429322, 8192, 52429836, 16384, 54526989, 16384, 54527502, 24576, 104859681, 262144, 155190306, 524288, 155191331, 1048576, 155191333, 2097152, 155191337, 4194304, 54528044, 32768, 4196400, 32768, 104858681, 131072, 104859194, 196608, 104858171, 131072, 104858684, 262144, 104859197, 393216, 104858686, 524288, 104858175, 262144, 102761537, 131072, 102761538, 262144, 102761539, 524288, 102761540, 1048576, 102761541, 2097152, 155190342, 4194304, 155191367, 8388608, 104860744, 3145728, 104861769, 4194304, 155192394, 6291456, 155193419, 8388608, 155192396, 12582912, 155193421, 16777216, 104863822, 6291456, 54528096, 16384, 54527078, 8192, 54527079, 16384, 54527080, 32768, 104859768, 1048576]
    idxes = analyze_table(table)
    print(len(idxes))
    print([chr(32+i) for i in idxes])
    print([table[i] for i in idxes])
