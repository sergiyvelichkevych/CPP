#!/usr/bin/env python3
import argparse, os, glob, struct, mmap, collections, csv, subprocess, sys, math
from pathlib import Path

HEADER_FMT = "<8sIIQII"   # magic(8), pid(u32), tid(u32), start_ns(u64), rec_size(u32), flags(u32)
RECORD_FMT = "<QQB7x"     # ts(u64), fn(u64), type(u8), pad(7)
HEADER_SZ  = struct.calcsize(HEADER_FMT)
RECORD_SZ  = struct.calcsize(RECORD_FMT)

Agg = collections.namedtuple("Agg", "calls incl_ns excl_ns max_incl_ns")
def agg_add(a, calls=0, incl=0, excl=0, mx=0):
    if a is None: a = Agg(0,0,0,0)
    return Agg(a.calls+calls, a.incl_ns+incl, a.excl_ns+excl, max(a.max_incl_ns, mx))

def parse_maps(maps_path):
    # Return list of mappings: (start, end, offset, pathname, executable_flag, base_vma)
    maps = []
    with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            # e.g.: 55ed2cdd7000-55ed2cde0000 r-xp 00000000 08:01 12345 /path/to/bin
            parts = line.strip().split()
            if len(parts) < 5: continue
            addr, perms, offset = parts[0], parts[1], parts[2]
            path = parts[-1] if len(parts) >= 6 else ""
            if "x" not in perms:  # only code mappings
                continue
            s, e = addr.split("-")
            start = int(s, 16); end = int(e, 16)
            off = int(offset, 16)
            base_vma = start - off  # link-time VMA base
            maps.append((start, end, off, path, True, base_vma))
    # Sort for binary search
    maps.sort(key=lambda m: m[0])
    return maps

def find_module(maps, addr):
    # find mapping that contains addr
    lo, hi = 0, len(maps)-1
    while lo <= hi:
        mid = (lo+hi)//2
        s,e,off,path,execflag,base = maps[mid]
        if addr < s: hi = mid - 1
        elif addr >= e: lo = mid + 1
        else: return maps[mid]
    return None

def symbolize_batch(module, vmas):
    # Call addr2line once with many VMAs; returns dict vma->(func, fileline) (func demangled)
    # If addr2line is not available or fails, return {vma: (None, None), ...}
    try:
        # chunk to avoid super-long command lines
        out = {}
        CHUNK = 2048
        for i in range(0, len(vmas), CHUNK):
            chunk = vmas[i:i+CHUNK]
            args = ["addr2line", "-f", "-C", "-e", module] + [hex(v) for v in chunk]
            cp = subprocess.run(args, capture_output=True, text=True)
            if cp.returncode != 0:
                for v in chunk: out[v] = (None, None)
                continue
            lines = cp.stdout.splitlines()
            # addr2line prints pairs: function, file:line
            for j,v in enumerate(chunk):
                fn = lines[2*j] if 2*j < len(lines) else "??"
                fl = lines[2*j+1] if 2*j+1 < len(lines) else "??:0"
                out[v] = (fn if fn != "??" else None, fl if fl != "??:0" else None)
        return out
    except FileNotFoundError:
        return {v: (None, None) for v in vmas}

def load_header(f):
    hdr = f.read(HEADER_SZ)
    if len(hdr) != HEADER_SZ:
        raise RuntimeError("bad header length")
    magic,pid,tid,start_ns,rec_size,flags = struct.unpack(HEADER_FMT, hdr)
    if magic[:7] != b"FPROFv1":
        raise RuntimeError("bad magic")
    if rec_size != RECORD_SZ:
        raise RuntimeError(f"record size mismatch: file={rec_size}, expected={RECORD_SZ}")
    return pid, tid, start_ns, flags

def analyze_thread_file(path, global_aggs):
    stack = []  # list of frames: [ (fn, start_ns, child_ns) ]
    last_ts = None
    with open(path, "rb") as f:
        pid, tid, start_ns, flags = load_header(f)
        data = f.read()
        nrec = len(data) // RECORD_SZ
        view = memoryview(data)
        off = 0
        for _ in range(nrec):
            ts_ns, fn, typ = struct.unpack_from(RECORD_FMT, view, off)
            off += RECORD_SZ
            last_ts = ts_ns
            if typ == 0:  # enter
                stack.append([fn, ts_ns, 0])
            else:         # exit
                # Drain until we find a matching frame to handle exceptions/unwinds
                while stack:
                    top_fn, start, child = stack.pop()
                    incl = ts_ns - start if ts_ns >= start else 0
                    excl = incl - child if incl >= child else 0
                    # aggregate for top_fn
                    global_aggs[top_fn] = agg_add(global_aggs.get(top_fn), calls=1, incl=incl, excl=excl, mx=incl)
                    # attribute inclusive time to parent as child time
                    if stack:
                        stack[-1][2] += incl
                    if top_fn == fn:
                        break
                # if stack empty and no match found, nothing else to do
        # If frames remain (abrupt exit), close them at last_ts to keep totals conservative
        if last_ts is not None and stack:
            end_ts = last_ts
            while stack:
                top_fn, start, child = stack.pop()
                incl = end_ts - start if end_ts >= start else 0
                excl = incl - child if incl >= child else 0
                global_aggs[top_fn] = agg_add(global_aggs.get(top_fn), calls=1, incl=incl, excl=excl, mx=incl)
                if stack:
                    stack[-1][2] += incl

def main():
    ap = argparse.ArgumentParser(description="Analyze fprof logs")
    ap.add_argument("logdir", help="Directory containing *.bin + <pid>.maps")
    ap.add_argument("--out", default="report.csv", help="Output CSV path")
    ap.add_argument("--top", type=int, default=0, help="Only write top N by exclusive time")
    ap.add_argument("--no-symbols", action="store_true", help="Do not run addr2line; show addresses only")
    args = ap.parse_args()

    logdir = Path(args.logdir)
    bins = sorted(glob.glob(str(logdir / "*.bin")))
    if not bins:
        print("No .bin logs found in", logdir, file=sys.stderr); sys.exit(1)

    # If multiple pids exist, pick the first maps file (or prefer the one matching the first bin prefix).
    maps_files = sorted(glob.glob(str(logdir / "*.maps")))
    if not maps_files:
        print("WARNING: no .maps file found; symbolization may be limited.", file=sys.stderr)
        maps = []
    else:
        maps = parse_maps(maps_files[0])

    # 1) Aggregate across all threads
    aggs = {}  # addr -> Agg
    for p in bins:
        try:
            analyze_thread_file(p, aggs)
        except Exception as e:
            print(f"Failed to parse {p}: {e}", file=sys.stderr)

    if not aggs:
        print("No events aggregated.", file=sys.stderr); sys.exit(1)

    # 2) Symbolize unique addresses
    addr_to_module = {}
    module_to_vmas = collections.defaultdict(set)
    for addr in aggs.keys():
        m = find_module(maps, addr) if maps else None
        if m:
            start,end,off,path,_,base_vma = m
            vma = addr - base_vma  # convert runtime address to link-time VMA
            addr_to_module[addr] = (path, vma)
            module_to_vmas[path].add(vma)
        else:
            addr_to_module[addr] = (None, None)

    addr_to_name = {}
    if not args.no_symbols and module_to_vmas:
        for mod, vmas in module_to_vmas.items():
            sym = symbolize_batch(mod, sorted(vmas))
            for vma, (fn, fl) in sym.items():
                addr_to_name[(mod, vma)] = fn

    # 3) Write CSV
    rows = []
    for addr, a in aggs.items():
        mod, vma = addr_to_module.get(addr, (None, None))
        name = addr_to_name.get((mod, vma))
        func_disp = name if name else ("0x%x" % addr)
        mod_disp  = mod if mod else ""
        avg_incl = a.incl_ns / a.calls if a.calls else 0.0
        avg_excl = a.excl_ns / a.calls if a.calls else 0.0
        rows.append((mod_disp, func_disp, a.calls, a.incl_ns, a.excl_ns, int(avg_incl), int(avg_excl), a.max_incl_ns))

    # sort by total exclusive time desc
    rows.sort(key=lambda r: r[4], reverse=True)
    if args.top > 0:
        rows = rows[:args.top]

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["module","function","calls","total_inclusive_ns","total_exclusive_ns","avg_inclusive_ns","avg_exclusive_ns","max_inclusive_ns"])
        w.writerows(rows)

    print(f"Wrote {args.out} with {len(rows)} rows.")

if __name__ == "__main__":
    main()