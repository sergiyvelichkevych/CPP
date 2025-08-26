#!/usr/bin/env python3
"""
fprof_analyze_threads.py

Reads per-thread binary logs produced by prof_log_fast.cpp and emits:
  1) A combined CSV across all threads (and all PIDs seen in the directory).
  2) Per-thread CSVs (one file per TID).
  3) Per-PID combined CSVs (useful when the directory holds multiple runs).

Columns:
  module,function,calls,total_inclusive_ns,total_exclusive_ns,
  avg_inclusive_ns,avg_exclusive_ns,max_inclusive_ns

Requirements:
  - Python 3.8+
  - GNU binutils 'addr2line' available on PATH for symbolization (optional).
  - Binaries built with '-g' (recommended) to resolve function names.

Typical usage:
  python3 fprof_analyze_threads.py /tmp/fprof-12345 --out-prefix report
  # Produces:
  #   report_combined.csv                          (all PIDs/threads)
  #   report_pid_12345_combined.csv               (per-PID combined)
  #   report_pid_12345_tid_67890.csv              (per-thread)
  #   ...

Notes:
  - If symbolization is disabled or symbols are stripped, function shows as hex address.
  - Sorting defaults to total_exclusive_ns (desc). Use --sort to change.
"""

import argparse
import collections
import csv
import glob
import mmap
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, Tuple, List, Optional, Iterable

# --- Log format (must match prof_log_fast.cpp) ---
HEADER_FMT = "<8sIIQII"   # magic(8), pid(u32), tid(u32), start_ns(u64), rec_size(u32), flags(u32)
RECORD_FMT = "<QQB7x"     # ts(u64), fn(u64), type(u8), pad(7)
HEADER_SZ  = struct.calcsize(HEADER_FMT)
RECORD_SZ  = struct.calcsize(RECORD_FMT)

Agg = collections.namedtuple("Agg", "calls incl_ns excl_ns max_incl_ns")

def agg_add(a: Optional[Agg], calls=0, incl=0, excl=0, mx=0) -> Agg:
    if a is None:
        return Agg(calls, incl, excl, mx)
    return Agg(a.calls + calls, a.incl_ns + incl, a.excl_ns + excl, max(a.max_incl_ns, mx))


# --- /proc/<pid>/maps parsing for module & load bias ---
def parse_maps(maps_path: Path):
    """
    Parses an ELF memory map file and returns a list of executable mappings:
      (start, end, offset, path, base_vma)
    where base_vma = start - offset (the link-time VMA base / load bias).
    """
    mappings = []
    with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            # Example: 55ed2cdd7000-55ed2cde0000 r-xp 00000000 08:01 12345 /path/to/bin
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            addr, perms, offset = parts[0], parts[1], parts[2]
            path = parts[-1] if len(parts) >= 6 else ""
            if "x" not in perms:  # only executable segments
                continue
            try:
                s, e = addr.split("-")
                start = int(s, 16)
                end   = int(e, 16)
                off   = int(offset, 16)
            except Exception:
                continue
            base_vma = start - off
            mappings.append((start, end, off, path, base_vma))
    mappings.sort(key=lambda m: m[0])
    return mappings

def find_module(mappings, addr: int):
    """Binary search for the mapping containing 'addr'. Returns mapping tuple or None."""
    lo, hi = 0, len(mappings) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, off, path, base_vma = mappings[mid]
        if addr < start:
            hi = mid - 1
        elif addr >= end:
            lo = mid + 1
        else:
            return mappings[mid]
    return None


# --- Symbolization helpers ---
def symbolize_batch(module_path: str, vmas: List[int]) -> Dict[int, Tuple[Optional[str], Optional[str]]]:
    """
    Runs 'addr2line -f -C -e <module> <addr>...' and returns:
      vma -> (function_name or None, file:line or None)
    """
    out = {}
    if not module_path or not os.path.exists(module_path):
        for v in vmas:
            out[v] = (None, None)
        return out
    try:
        CHUNK = 2048  # avoid overly long argv
        for i in range(0, len(vmas), CHUNK):
            chunk = vmas[i:i+CHUNK]
            cmd = ["addr2line", "-f", "-C", "-e", module_path] + [hex(v) for v in chunk]
            cp = subprocess.run(cmd, capture_output=True, text=True)
            if cp.returncode != 0:
                for v in chunk:
                    out[v] = (None, None)
                continue
            lines = cp.stdout.splitlines()
            for j, v in enumerate(chunk):
                # addr2line emits pairs: function\nfile:line\n
                fn = lines[2*j] if 2*j   < len(lines) else "??"
                fl = lines[2*j+1] if 2*j+1 < len(lines) else "??:0"
                out[v] = (fn if fn != "??" else None, fl if fl != "??:0" else None)
        return out
    except FileNotFoundError:
        # addr2line missing
        return {v: (None, None) for v in vmas}


# --- Binary reader ---
def load_header(mm: mmap.mmap) -> Tuple[int, int, int, int]:
    hdr = mm[:HEADER_SZ]
    if len(hdr) != HEADER_SZ:
        raise RuntimeError("bad header length")
    magic, pid, tid, start_ns, rec_size, flags = struct.unpack(HEADER_FMT, hdr)
    if magic[:7] != b"FPROFv1":
        raise RuntimeError("bad magic in {}".format(magic))
    if rec_size != RECORD_SZ:
        raise RuntimeError(f"record size mismatch: file={rec_size}, expected={RECORD_SZ}")
    return pid, tid, start_ns, flags

def analyze_thread_file(bin_path: Path) -> Tuple[int, int, Dict[int, Agg]]:
    """
    Reconstructs per-function aggregates for a single thread log.
    Returns (pid, tid, {addr: Agg})
    """
    aggs: Dict[int, Agg] = {}
    with open(bin_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            pid, tid, start_ns, flags = load_header(mm)
            pos = HEADER_SZ
            end = mm.size()
            stack: List[List[int]] = []  # [fn_addr, start_ns, child_ns]
            last_ts = None

            while pos + RECORD_SZ <= end:
                ts_ns, fn, typ = struct.unpack_from(RECORD_FMT, mm, pos)
                pos += RECORD_SZ
                last_ts = ts_ns
                if typ == 0:  # enter
                    stack.append([fn, ts_ns, 0])
                else:  # exit
                    # Drain until match to handle exception unwinds
                    while stack:
                        top_fn, start, child = stack.pop()
                        incl = ts_ns - start if ts_ns >= start else 0
                        excl = incl - child if incl >= child else 0
                        aggs[top_fn] = agg_add(aggs.get(top_fn), calls=1, incl=incl, excl=excl, mx=incl)
                        if stack:
                            stack[-1][2] += incl
                        if top_fn == fn:
                            break
            # If frames remain (abrupt termination), close at last_ts conservatively
            if last_ts is not None and stack:
                end_ts = last_ts
                while stack:
                    top_fn, start, child = stack.pop()
                    incl = end_ts - start if end_ts >= start else 0
                    excl = incl - child if incl >= child else 0
                    aggs[top_fn] = agg_add(aggs.get(top_fn), calls=1, incl=incl, excl=excl, mx=incl)
                    if stack:
                        stack[-1][2] += incl

            return pid, tid, aggs
        finally:
            mm.close()


# --- Aggregation & Reporting ---
def merge_aggs(dst: Dict[int, Agg], src: Dict[int, Agg]) -> None:
    for addr, a in src.items():
        dst[addr] = agg_add(dst.get(addr), calls=a.calls, incl=a.incl_ns, excl=a.excl_ns, mx=a.max_incl_ns)

def build_symbol_cache(
    per_pid_addr_sets: Dict[int, Iterable[int]],
    pid_to_maps: Dict[int, List[Tuple[int,int,int,str,int]]],
    no_symbols: bool
):
    """
    Returns two dicts:
      addr2modvma[(pid, addr)] = (module_path or "", vma or None)
      name_cache[(pid, module_path, vma)] = demangled_name or None
    """
    addr2modvma: Dict[Tuple[int,int], Tuple[str, Optional[int]]] = {}
    name_cache: Dict[Tuple[int,str,int], Optional[str]] = {}

    # First, map every address to (module, vma) using maps
    module_addr_sets: Dict[Tuple[int,str], set] = collections.defaultdict(set)
    for pid, addrs in per_pid_addr_sets.items():
        maps = pid_to_maps.get(pid)
        for addr in addrs:
            mod_path = ""
            vma = None
            if maps:
                m = find_module(maps, addr)
                if m:
                    start, end, off, path, base_vma = m
                    mod_path = path or ""
                    vma = addr - base_vma
                    module_addr_sets[(pid, mod_path)].add(vma)
            addr2modvma[(pid, addr)] = (mod_path, vma)

    # Then, run addr2line per (pid,module) to get names
    if not no_symbols:
        for (pid, mod_path), vmas in module_addr_sets.items():
            if not mod_path or not vmas:
                continue
            sym = symbolize_batch(mod_path, sorted(vmas))
            for v, (fn, _fl) in sym.items():
                name_cache[(pid, mod_path, v)] = fn

    return addr2modvma, name_cache

def rows_from_aggs(
    pid: int,
    aggs: Dict[int, Agg],
    addr2modvma: Dict[Tuple[int,int], Tuple[str, Optional[int]]],
    name_cache: Dict[Tuple[int,str,int], Optional[str]],
    sort_by: str,
    top_n: int
):
    rows = []
    for addr, a in aggs.items():
        mod, vma = addr2modvma.get((pid, addr), ("", None))
        name = name_cache.get((pid, mod, vma)) if (vma is not None) else None
        func_disp = name if name else f"0x{addr:x}"
        avg_incl = int(a.incl_ns / a.calls) if a.calls else 0
        avg_excl = int(a.excl_ns / a.calls) if a.calls else 0
        rows.append([mod, func_disp, a.calls, a.incl_ns, a.excl_ns, avg_incl, avg_excl, a.max_incl_ns])

    key_idx = {"exclusive": 4, "inclusive": 3, "calls": 2}[sort_by]
    rows.sort(key=lambda r: r[key_idx], reverse=True)
    if top_n > 0:
        rows = rows[:top_n]
    return rows

def write_csv(out_path: Path, rows: List[List], header=True):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        if header:
            w.writerow([
                "module","function","calls",
                "total_inclusive_ns","total_exclusive_ns",
                "avg_inclusive_ns","avg_exclusive_ns","max_inclusive_ns"
            ])
        w.writerows(rows)


# --- CLI / Main ---
def main():
    ap = argparse.ArgumentParser(description="Analyze fprof logs and emit per-thread and combined CSVs.")
    ap.add_argument("logdir", help="Directory containing *.bin (and <pid>.maps)")
    ap.add_argument("--out-prefix", default="report",
                    help="Output prefix (default: report). Files like <prefix>_combined.csv, <prefix>_pid_<pid>_tid_<tid>.csv")
    ap.add_argument("--top", type=int, default=0, help="Only include top N rows per CSV (0 = all).")
    ap.add_argument("--no-symbols", action="store_true", help="Skip addr2line lookups; print addresses.")
    ap.add_argument("--sort", choices=["exclusive", "inclusive", "calls"], default="exclusive",
                    help="Sort key for CSVs (default: exclusive).")
    args = ap.parse_args()

    logdir = Path(args.logdir)
    if not logdir.exists():
        print(f"Log directory not found: {logdir}", file=sys.stderr)
        sys.exit(1)

    bin_paths = sorted(Path(p) for p in glob.glob(str(logdir / "*.bin")))
    if not bin_paths:
        print(f"No .bin logs found in {logdir}", file=sys.stderr)
        sys.exit(1)

    # Parse all threads
    per_thread: Dict[Tuple[int,int], Dict[int, Agg]] = {}  # (pid,tid) -> {addr -> Agg}
    pids_seen = set()
    for p in bin_paths:
        try:
            pid, tid, aggs = analyze_thread_file(p)
            per_thread[(pid, tid)] = aggs
            pids_seen.add(pid)
        except Exception as e:
            print(f"Failed to parse {p}: {e}", file=sys.stderr)

    if not per_thread:
        print("No data aggregated.", file=sys.stderr)
        sys.exit(1)

    # Build per-PID combined and global combined
    per_pid_combined: Dict[int, Dict[int, Agg]] = collections.defaultdict(dict)
    global_combined: Dict[Tuple[int,int], Agg] = {}  # (pid,addr)->Agg (keep pid to avoid addr collisions across PIDs)
    for (pid, tid), aggs in per_thread.items():
        # Merge into per-PID dict keyed by raw addr
        merge_aggs(per_pid_combined[pid], aggs)
        # Merge into global combined keyed by (pid,addr)
        for addr, a in aggs.items():
            global_combined[(pid, addr)] = agg_add(global_combined.get((pid, addr)),
                                                   calls=a.calls, incl=a.incl_ns, excl=a.excl_ns, mx=a.max_incl_ns)

    # Load maps per PID if available
    pid_to_maps: Dict[int, List[Tuple[int,int,int,str,int]]] = {}
    maps_files = {int(Path(m).stem.split(".")[0]): Path(m) for m in glob.glob(str(logdir / "*.maps")) if re.match(r"\d+\.maps$", Path(m).name)}
    for pid in pids_seen:
        mp = maps_files.get(pid)
        if mp and mp.exists():
            try:
                pid_to_maps[pid] = parse_maps(mp)
            except Exception as e:
                print(f"Warning: failed to parse {mp}: {e}", file=sys.stderr)
        else:
            # If missing, we proceed without symbols for this PID.
            pass

    # Build symbol caches:
    #   1) address sets per PID (union across that PID's threads)
    per_pid_addr_sets: Dict[int, set] = {pid: set() for pid in pids_seen}
    for pid in pids_seen:
        for addr in per_pid_combined[pid].keys():
            per_pid_addr_sets[pid].add(addr)

    addr2modvma, name_cache = build_symbol_cache(per_pid_addr_sets, pid_to_maps, args.no_symbols)

    # Write per-thread CSVs
    out_prefix = Path(args.out_prefix)
    for (pid, tid), aggs in per_thread.items():
        rows = rows_from_aggs(pid, aggs, addr2modvma, name_cache, args.sort, args.top)
        out_path = out_prefix.parent / f"{out_prefix.name}_pid_{pid}_tid_{tid}.csv"
        write_csv(out_path, rows)

    # Write per-PID combined CSVs
    for pid, aggs in per_pid_combined.items():
        rows = rows_from_aggs(pid, aggs, addr2modvma, name_cache, args.sort, args.top)
        out_path = out_prefix.parent / f"{out_prefix.name}_pid_{pid}_combined.csv"
        write_csv(out_path, rows)

    # Write global combined (across all PIDs/threads)
    # We re-shape into a "fake PID" view by keeping PID as a column? For simplicity we
    # keep same columns and resolve names with that PID's maps; if multiple PIDs exist,
    # identical functions from different processes appear as separate rows.
    global_rows = []
    for (pid, addr), a in global_combined.items():
        mod, vma = addr2modvma.get((pid, addr), ("", None))
        name = name_cache.get((pid, mod, vma)) if (vma is not None) else None
        func_disp = name if name else f"0x{addr:x}"
        avg_incl = int(a.incl_ns / a.calls) if a.calls else 0
        avg_excl = int(a.excl_ns / a.calls) if a.calls else 0
        # To make the global file self-contained, prefix module with [pid]:
        mod_disp = f"[pid {pid}] {mod}" if mod else f"[pid {pid}]"
        global_rows.append([mod_disp, func_disp, a.calls, a.incl_ns, a.excl_ns, avg_incl, avg_excl, a.max_incl_ns])

    key_idx = {"exclusive": 4, "inclusive": 3, "calls": 2}[args.sort]
    global_rows.sort(key=lambda r: r[key_idx], reverse=True)
    if args.top > 0:
        global_rows = global_rows[:args.top]
    write_csv(out_prefix.parent / f"{out_prefix.name}_combined.csv", global_rows)

    # Summary
    print(f"Threads analyzed: {len(per_thread)} across PIDs: {sorted(pids_seen)}")
    print(f"Wrote: {out_prefix.name}_combined.csv")
    for pid in sorted(pids_seen):
        print(f"Wrote: {out_prefix.name}_pid_{pid}_combined.csv")
    for (pid, tid) in sorted(per_thread.keys()):
        print(f"Wrote: {out_prefix.name}_pid_{pid}_tid_{tid}.csv")


if __name__ == "__main__":
    main()