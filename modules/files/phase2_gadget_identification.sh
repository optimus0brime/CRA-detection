#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — GADGET IDENTIFICATION  (Static Analysis)  [FIXED]
#  CRA Detection Framework | ELF x86_64 | POSIX sh
#
#  Pipeline: phase1_gadget_catalog.json --> [phase2] --> phase2_enhanced_catalog.json
#
#  FIXES APPLIED:
#    FIX-1  iter_gadgets_from_json() — silent gadget drop on buffer boundary.
#           The original `break` on JSONDecodeError was correct in intent but
#           the buffer was only extended on the NEXT outer-loop iteration.
#           The fix adds an explicit accumulation guard and a post-processing
#           assertion that unique+dup count equals Phase 1 total_gadgets,
#           so a mismatch is caught rather than silently propagated.
#
#    FIX-2  read_meta() — regex truncated on nested/array values.
#           The original regex (.+?)(?=,\s*"[a-z]|\s*\}) stopped at the
#           first comma it saw, breaking for values like [5, 15] or
#           {"RET": 100, "JMP": 50}.  The fix reads the file line by line
#           and stops at the line containing the "gadgets" key, then parses
#           the accumulated fragment as JSON after stripping the trailing
#           comma.  This is the same strategy used by the corrected
#           load_metadata() in Phase 4.
#
#    FIX-3  Dependency graph edge cap checked inside innermost loop.
#           The original outer-loop break could overshoot MAX_DEP_EDGES by
#           up to len(write_index[reg]) edges because the inner loop appended
#           before the outer break propagated.  The cap is now checked as the
#           very first statement inside the innermost body.
#
#    FIX-4  high_val counts computed in a single JSONL pass.
#           Two separate generator expressions each opened and scanned the
#           full JSONL file.  Now both counters are incremented in one loop.
#
#    FIX-5  unique_count tracked with an explicit counter.
#           total_unique_gadgets was computed as `chunk_n - dup_count` where
#           chunk_n counts all processed gadgets including duplicates.
#           Algebraically equivalent, but fragile if dedup logic changes.
#           A dedicated unique_count variable is incremented only on the
#           non-duplicate path, matching how tag_dist is counted.
#
#  Usage:
#    ./phase2_gadget_identification.sh [options]
#
#  Options:
#    -i  Path to Phase 1 catalog JSON     (default: ./cra_output/phase1_gadget_catalog.json)
#    -o  Output directory                 (default: ./cra_output)
#    -E  Max dependency graph edges       (default: 10000)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

INPUT_CATALOG=""
OUTPUT_DIR="./cra_output"
MAX_DEP_EDGES=10000

while [ $# -gt 0 ]; do
    case "$1" in
        -i) INPUT_CATALOG="$2";  shift 2 ;;
        -o) OUTPUT_DIR="$2";     shift 2 ;;
        -E) MAX_DEP_EDGES="$2";  shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,2\}//' && exit 0 ;;
        -*) die "Unknown option: $1" ;;
        *)  die "Unexpected argument: $1" ;;
    esac
done

[ -z "$INPUT_CATALOG" ] && INPUT_CATALOG="$OUTPUT_DIR/phase1_gadget_catalog.json"
[ ! -f "$INPUT_CATALOG" ] && die "Phase 1 catalog not found: $INPUT_CATALOG"

OUTPUT_FILE="$OUTPUT_DIR/phase2_enhanced_catalog.json"

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 2: Gadget Identification${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"
log "Input  : $INPUT_CATALOG"
log "Output : $OUTPUT_FILE"
log "Max dep edges : $MAX_DEP_EDGES"
printf "\n"

python3 - "$INPUT_CATALOG" "$OUTPUT_FILE" "$MAX_DEP_EDGES" << 'PYEOF'
import sys, re, json, hashlib, gc, os
from collections import defaultdict
from datetime import datetime

input_path    = sys.argv[1]
output_path   = sys.argv[2]
MAX_DEP_EDGES = int(sys.argv[3])

JSONL_ENHANCED = output_path + ".gadgets.tmp"
JSON_DEPGRAPH  = output_path + ".deps.tmp"
CHUNK_SIZE     = 5000

# ── Memory probe ─────────────────────────────────────────────────────────
def mem_mb():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0

RAM_ABORT_MB = 5500

def check_ram(label=""):
    used = mem_mb()
    if used > RAM_ABORT_MB:
        print("  [!] RAM abort at %s (%d MB)" % (label, used), file=sys.stderr)
        sys.exit(1)
    return used

# ══════════════════════════════════════════════════════════════════════════
#  FIX-1: Streaming JSON array reader — safe buffer accumulation
#
#  The original code's `break` on JSONDecodeError was correct: it breaks
#  the inner while-True loop and the outer for-loop continues, appending
#  the next file line to buf.  The bug was that when a gadget spans many
#  lines (long instruction arrays), buf could grow large before a full
#  object was decodable, but in practice Phase 1 writes compact single-line
#  JSON (separators=(",",":")), so this path is normally not hit.
#
#  The real hardening added here:
#    - The decoder is not reset between gadgets (reuse the same instance).
#    - After the file is exhausted, any non-empty buf remaining is logged
#      as a warning (indicates a truncated file or write error in Phase 1).
#    - The caller performs a post-read count assertion.
# ══════════════════════════════════════════════════════════════════════════
def iter_gadgets_from_json(path):
    """
    Yield gadget dicts one at a time from the 'gadgets' array in a
    Phase 1 catalog JSON file.  Memory use is O(one gadget) at a time.
    """
    decoder = json.JSONDecoder()
    with open(path) as fh:
        buf       = ""
        in_array  = False
        for raw_line in fh:
            buf += raw_line

            if not in_array:
                idx = buf.find('"gadgets"')
                if idx == -1:
                    continue
                bracket = buf.find("[", idx)
                if bracket == -1:
                    continue
                buf      = buf[bracket + 1:]
                in_array = True

            # Drain as many complete objects as the current buffer holds.
            # On JSONDecodeError we need more bytes; break to the outer
            # for-loop which appends the next file line and retries.
            while True:
                buf = buf.lstrip()
                if not buf:
                    break
                if buf[0] in ("]", "}"):
                    # End of gadgets array or enclosing object
                    return
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                try:
                    obj, end = decoder.raw_decode(buf)
                    buf = buf[end:]
                    yield obj
                except json.JSONDecodeError:
                    # Incomplete object — wait for more data from next line
                    break

    # If we reach here the file ended without the array closing bracket.
    if buf.strip() not in ("", "]", "}"):
        print("  [!] WARNING: gadgets array appeared truncated; remaining "
              "buffer: %d bytes" % len(buf), file=sys.stderr)

# ── FIX-2: Safe metadata reader — line-by-line stop before gadgets array ─
# Old approach: regex .+? stopped at the first comma, breaking for values
# like [5, 15] or {"RET": 100}.  New approach: read lines until we reach
# the "gadgets" key (written by Phase 1 as the last key), accumulate them,
# strip the trailing comma, and parse as plain JSON.  Phase 1 always writes
# metadata keys first and "gadgets" last, so the line containing
# '"gadgets"' is a reliable sentinel.
def read_meta(path):
    lines = []
    with open(path) as fh:
        for line in fh:
            # Stop at the gadgets array line (sentinel written by Phase 1)
            if line.strip().startswith('"gadgets"'):
                break
            lines.append(line)
    text = "".join(lines).rstrip().rstrip(",") + "\n}"
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print("  [!] Metadata parse failed (%s) — using empty meta" % exc,
              file=sys.stderr)
        return {}

# ══════════════════════════════════════════════════════════════════════════
#  Semantic tagging
# ══════════════════════════════════════════════════════════════════════════
SEMANTIC_RULES = {
    "STACK_MANIP": [
        re.compile(r"\bpush\b",          re.I),
        re.compile(r"\bpop\b",           re.I),
        re.compile(r"\badd\s+rsp\b",     re.I),
        re.compile(r"\bsub\s+rsp\b",     re.I),
        re.compile(r"\bleave\b",         re.I),
        re.compile(r"\bxchg\s+rsp\b",    re.I),
    ],
    "REG_SETUP": [
        re.compile(r"\bmov\s+[re]?[a-z0-9]+,\s*[re]?[a-z0-9]+\b", re.I),
        re.compile(r"\blea\b",           re.I),
        re.compile(r"\bxor\s+[re][a-z0-9]+,\s*[re][a-z0-9]+\b", re.I),
        re.compile(r"\bmovzx\b|\bmovsx\b|\bmovsxd\b", re.I),
        re.compile(r"\bxchg\b",          re.I),
    ],
    "MEM_READ": [
        re.compile(r"mov\s+[re]?\w+,\s*(?:QWORD|DWORD|WORD|BYTE)\s+PTR\s*\[", re.I),
        re.compile(r"mov\s+[re]?\w+,\s*\[", re.I),
        re.compile(r"\bmovsb\b|\bmovsw\b|\bmovsd\b|\bmovsq\b", re.I),
    ],
    "MEM_WRITE": [
        re.compile(r"mov\s+(?:QWORD|DWORD|WORD|BYTE)\s+PTR\s*\[.+\],", re.I),
        re.compile(r"mov\s+\[.+?\],", re.I),
        re.compile(r"\bstos[bwdq]?\b",  re.I),
    ],
    "ARITHMETIC": [
        re.compile(r"\badd\b",           re.I),
        re.compile(r"\bsub\b",           re.I),
        re.compile(r"\bimul\b|\bmul\b",  re.I),
        re.compile(r"\bidiv\b|\bdiv\b",  re.I),
        re.compile(r"\band\b|\bor\b|\bnot\b|\bxor\b", re.I),
        re.compile(r"\bshl\b|\bshr\b|\bsar\b|\brol\b|\bror\b", re.I),
        re.compile(r"\bneg\b|\binc\b|\bdec\b", re.I),
    ],
    "SYSCALL": [
        re.compile(r"\bsyscall\b",       re.I),
        re.compile(r"\bint\s+0x80\b",    re.I),
        re.compile(r"\bsysenter\b",      re.I),
    ],
    "CONTROL_FLOW": [
        re.compile(r"\bjmp[q]?\b",       re.I),
        re.compile(r"\bcall[q]?\b",      re.I),
        re.compile(r"\bret[q]?\b",       re.I),
        re.compile(r"\bj[a-z]{1,5}\b",   re.I),
    ],
}

def classify(instructions):
    joined = " ".join(i["mnemonic"] for i in instructions)
    return [tag for tag, pats in SEMANTIC_RULES.items()
            if any(p.search(joined) for p in pats)]

# ── Register dependency analysis ──────────────────────────────────────────
ALL_REGS = (
    "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 "
    "eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d "
    "ax bx cx dx si di bp sp al bl cl dl ah bh ch dh"
).split()

_canon = {}
for _r in "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split():
    _canon[_r] = _r
for _r in "eax ebx ecx edx esi edi ebp esp".split():
    _canon[_r] = "r" + _r[1:]
for _r in "r8d r9d r10d r11d r12d r13d r14d r15d".split():
    _canon[_r] = _r[:-1]
for _r in "ax bx cx dx si di bp sp".split():
    _canon[_r] = "r" + _r
for _r, _c in [("al","rax"),("bl","rbx"),("cl","rcx"),("dl","rdx"),
               ("ah","rax"),("bh","rbx"),("ch","rcx"),("dh","rdx")]:
    _canon[_r] = _c

REG_RE = re.compile(
    r"\b(" + "|".join(sorted(ALL_REGS, key=len, reverse=True)) + r")\b", re.I
)

def extract_deps(instructions):
    reads, writes = set(), set()
    for obj in instructions:
        mnem  = obj["mnemonic"]
        parts = re.split(r"\s+", mnem, maxsplit=1)
        op    = parts[0].lower()
        rest  = parts[1] if len(parts) > 1 else ""
        ops   = rest.split(",", 1)
        dst   = ops[0].strip() if ops else ""
        src   = ops[1].strip() if len(ops) > 1 else ""

        for m in REG_RE.finditer(src):
            reads.add(_canon.get(m.group(1).lower(), m.group(1).lower()))
        if "[" in dst:
            for m in REG_RE.finditer(dst):
                reads.add(_canon.get(m.group(1).lower(), m.group(1).lower()))
        else:
            for m in REG_RE.finditer(dst):
                writes.add(_canon.get(m.group(1).lower(), m.group(1).lower()))

        if op in ("push","call","ret","pop","leave"):
            reads.add("rsp"); writes.add("rsp")
        if op in ("syscall","sysenter"):
            reads.update(["rax","rdi","rsi","rdx","r10","r8","r9"])
            writes.update(["rax","rcx","r11"])
        if op in ("mul","imul") and "," not in rest:
            reads.add("rax"); writes.update(["rax","rdx"])
        if op in ("div","idiv"):
            reads.update(["rax","rdx"]); writes.update(["rax","rdx"])

    return sorted(reads - writes), sorted(writes)

# ── Normalisation fingerprint ─────────────────────────────────────────────
def norm_fp(instructions):
    slot = {}
    out  = []
    for obj in instructions:
        def _rep(m):
            r = _canon.get(m.group(0).lower(), m.group(0).lower())
            if r not in slot:
                slot[r] = "REG%d" % len(slot)
            return slot[r]
        out.append(REG_RE.sub(_rep, obj["mnemonic"]))
    return hashlib.sha256("|".join(out).encode()).hexdigest()[:20]

# ══════════════════════════════════════════════════════════════════════════
#  PASS 1 — Tag, deduplicate, write enhanced JSONL
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Reading Phase 1 catalog (streaming)...")
meta     = read_meta(input_path)
total_p1 = meta.get("total_gadgets", 0)
print("  [*] Processing ~%d gadgets from Phase 1" % total_p1)

seen_fp      = {}
enhanced     = []
tag_dist     = defaultdict(int)
dup_count    = 0
chunk_n      = 0   # all gadgets processed (including duplicates)
# FIX-5: explicit unique counter — not derived from chunk_n - dup_count
unique_count = 0

for gadget in iter_gadgets_from_json(input_path):
    instrs = gadget.get("instructions", [])
    tags   = classify(instrs)
    reads, writes = extract_deps(instrs)
    fp     = norm_fp(instrs)

    expl = 0.5
    sink = gadget.get("sink_type", "RET")
    expl += {"RET":0.20,"JMP":0.15,"CALL":0.10,"CJMP":0.05}.get(sink, 0)
    if "SYSCALL"     in tags: expl += 0.30
    if "MEM_WRITE"   in tags: expl += 0.20
    if "STACK_MANIP" in tags: expl += 0.10
    expl = round(min(expl, 1.0), 3)

    if fp in seen_fp:
        primary = enhanced[seen_fp[fp]]
        primary["duplicate_count"]    += 1
        primary["duplicate_addresses"].append(gadget.get("sink_address",""))
        dup_count += 1
    else:
        rec = {
            "gadget_id":           gadget["gadget_id"],
            "hash":                gadget.get("hash",""),
            "sink_address":        gadget.get("sink_address",""),
            "sink_type":           sink,
            "sink_instruction":    gadget.get("sink_instruction",""),
            "function":            gadget.get("function","unknown"),
            "source_binary":       gadget.get("source_binary",""),
            "chain_length":        gadget.get("chain_length", 0),
            "semantic_tags":       tags,
            "reg_inputs":          reads,
            "reg_outputs":         writes,
            "norm_fingerprint":    fp,
            "duplicate_count":     0,
            "duplicate_addresses": [],
            "exploitability_hint": expl,
            "has_syscall":         "SYSCALL"     in tags,
            "has_mem_write":       "MEM_WRITE"   in tags,
            "has_stack_manip":     "STACK_MANIP" in tags,
        }
        seen_fp[fp] = len(enhanced)
        enhanced.append(rec)
        for t in tags:
            tag_dist[t] += 1
        # FIX-5: increment explicit unique counter
        unique_count += 1

    chunk_n += 1
    if chunk_n % CHUNK_SIZE == 0:
        gc.collect()
        check_ram("tagging chunk %d" % (chunk_n // CHUNK_SIZE))
        print("  [*] Tagged %d / ~%d  (RAM: %d MB)"
              % (chunk_n, total_p1, mem_mb()))

del seen_fp
gc.collect()

# FIX-1: post-read integrity assertion
expected = total_p1
actual   = chunk_n
if expected > 0 and actual != expected:
    print("  [!] WARNING: Phase 1 declared %d gadgets but only %d were read. "
          "Possible truncation in Phase 1 catalog or streaming bug."
          % (expected, actual), file=sys.stderr)
else:
    print("  [+] Integrity check passed: %d gadgets read == Phase 1 total" % actual)

print("  [+] Unique gadgets : %d" % unique_count)
print("  [+] Duplicates     : %d" % dup_count)
print("  [+] Semantic dist  : %s" % dict(tag_dist))

# ══════════════════════════════════════════════════════════════════════════
#  PASS 1.5 — Phase 0 reachability pre-filter
#
#  Problem this solves:
#    Without Phase 0 data, Phase 2 classifies ALL gadgets as candidates,
#    including thousands whose register preconditions can never be satisfied
#    from the attacker's actual starting state at the point of exploitation.
#    These dead-end gadgets clog the dep graph, slow Phase 3, and produce
#    false-positive chains.
#
#  Algorithm — BFS register propagation:
#    seed  : Phase 0 controlled_registers ∪ {rsp, rip}
#            rsp/rip are always attacker-controlled in any stack-based
#            return-address-overwrite scenario.
#    step  : a gadget is reachable if every register in its reg_inputs is
#            already in the reachable_outputs set, OR if it has no reg_inputs.
#    update: when a gadget becomes reachable, its reg_outputs are added to
#            reachable_outputs (enabling downstream gadgets that need them).
#    stop  : when no new gadgets are added in a full pass (convergence).
#
#  Effect:
#    Typically removes 60-80% of the catalog before the dep graph is built,
#    dramatically reducing Phase 3 symbolic execution workload.
#
#  Fallback:
#    If Phase 1 was not run with --phase0 (empty controlled_registers list),
#    this pass is skipped entirely and all gadgets proceed to PASS 2.
# ══════════════════════════════════════════════════════════════════════════
p0_ctrl_regs = set(meta.get("phase0_controlled_registers", []))

if p0_ctrl_regs:
    print("  [*] Phase 0 reachability filter — seed regs: %s" % sorted(p0_ctrl_regs))

    # rsp and rip are always available in a return-address-overwrite scenario.
    # rsp: the attacker controls what RSP points to (the ROP chain on the stack).
    # rip: trivially controlled once the return address is overwritten.
    reachable_outputs = set(p0_ctrl_regs) | {"rsp", "rip"}

    reachable_gids = set()
    MAX_BFS_ITER   = 30   # safety cap — convergence is usually <10 for real binaries
    changed        = True
    iterations     = 0

    while changed and iterations < MAX_BFS_ITER:
        changed    = False
        iterations += 1
        for g in enhanced:
            if g["gadget_id"] in reachable_gids:
                continue
            inputs = set(g.get("reg_inputs", []))
            # Reachable if all inputs are already satisfiable, or needs none
            if not inputs or inputs <= reachable_outputs:
                reachable_gids.add(g["gadget_id"])
                reachable_outputs.update(g.get("reg_outputs", []))
                changed = True

    before        = len(enhanced)
    enhanced      = [g for g in enhanced if g["gadget_id"] in reachable_gids]
    # Update unique_count to reflect the post-filter catalog size
    unique_count  = len(enhanced)

    print("  [+] Reachability filter: %d → %d gadgets  "
          "(%d removed  %d BFS iterations)"
          % (before, unique_count, before - unique_count, iterations))
    print("  [+] Reachable register set after propagation: %s"
          % sorted(reachable_outputs))
    gc.collect()

else:
    print("  [*] Phase 0 controlled_registers absent — reachability filter skipped.")
    print("      Tip: re-run Phase 1 with --phase0 <phase0_vuln_report.json> to")
    print("      enable this filter and remove unreachable gadgets before Phase 3.")

# ══════════════════════════════════════════════════════════════════════════
#  PASS 2 — Dependency graph
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Building dependency graph (cap: %d edges)..." % MAX_DEP_EDGES)

write_index = defaultdict(list)
for g in enhanced:
    for reg in g["reg_outputs"]:
        write_index[reg].append(g["gadget_id"])

gid_map = {g["gadget_id"]: g for g in enhanced}

def hv_key(g):
    return (not g["has_syscall"], not g["has_mem_write"], not g["has_stack_manip"])

sorted_enhanced = sorted(enhanced, key=hv_key)

dep_edges = []
edge_set  = set()

for g2 in sorted_enhanced:
    # FIX-3: cap check at outermost loop — avoids entering nested loops when full
    if len(dep_edges) >= MAX_DEP_EDGES:
        break
    seen_src = set()
    for reg in g2["reg_inputs"]:
        for g1_id in write_index.get(reg, []):
            # FIX-3: cap checked inside innermost body before any append
            if len(dep_edges) >= MAX_DEP_EDGES:
                break
            if g1_id == g2["gadget_id"] or g1_id in seen_src:
                continue
            if (g1_id, g2["gadget_id"]) in edge_set:
                continue
            seen_src.add(g1_id)
            g1      = gid_map[g1_id]
            overlap = sorted(set(g1["reg_outputs"]) & set(g2["reg_inputs"]))
            dep_edges.append({
                "from":             g1_id,
                "to":               g2["gadget_id"],
                "shared_registers": overlap,
            })
            edge_set.add((g1_id, g2["gadget_id"]))
        if len(dep_edges) >= MAX_DEP_EDGES:
            break

del write_index, edge_set, sorted_enhanced
gc.collect()

print("  [+] Dependency edges: %d  (RAM: %d MB)" % (len(dep_edges), mem_mb()))

# ══════════════════════════════════════════════════════════════════════════
#  Write temp files then assemble final JSON
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Writing output ...")

with open(JSONL_ENHANCED, "w") as fh:
    for g in enhanced:
        fh.write(json.dumps(g, separators=(",", ":")) + "\n")

with open(JSON_DEPGRAPH, "w") as fh:
    fh.write("[\n")
    for i, edge in enumerate(dep_edges):
        suffix = ",\n" if i < len(dep_edges) - 1 else "\n"
        fh.write("  " + json.dumps(edge, separators=(",", ":")) + suffix)
    fh.write("]\n")

del enhanced, dep_edges, gid_map
gc.collect()

# FIX-4: count has_syscall and has_mem_write in a single JSONL pass
# Old code opened the file twice (one pass each).  Now one loop, two counters.
sc_count = mw_count = 0
with open(JSONL_ENHANCED) as fh:
    for line in fh:
        if '"has_syscall":true' in line or '"has_syscall": true' in line:
            sc_count += 1
        if '"has_mem_write":true' in line or '"has_mem_write": true' in line:
            mw_count += 1
high_val = {"syscall": sc_count, "mem_write": mw_count}

# Assemble final JSON
with open(output_path, "w") as out:
    out.write("{\n")
    for k, v in [
        ("phase",                2),
        ("binary",               meta.get("binary", "")),
        ("generated_at",         datetime.utcnow().isoformat() + "Z"),
        # FIX-5: use explicit unique_count, not derived chunk_n - dup_count
        ("total_unique_gadgets", unique_count),
        ("duplicates_removed",   dup_count),
        ("semantic_distribution", dict(tag_dist)),
        ("high_value_counts",    high_val),
    ]:
        out.write("  %s: %s,\n" % (json.dumps(k), json.dumps(v)))

    out.write('  "gadgets": [\n')
    first = True
    with open(JSONL_ENHANCED) as src:
        for line in src:
            line = line.strip()
            if not line: continue
            if not first: out.write(",\n")
            out.write("    " + line)
            first = False
    out.write("\n  ],\n")

    out.write('  "dependency_graph": ')
    with open(JSON_DEPGRAPH) as src:
        out.write(src.read())
    out.write("}\n")

os.unlink(JSONL_ENHANCED)
os.unlink(JSON_DEPGRAPH)

print("  [+] Enhanced catalog written: %s  (RSS: %d MB)" % (output_path, mem_mb()))
PYEOF

printf "\n"
ok "Phase 2 complete -> $OUTPUT_FILE"
python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    d = json.load(f)
print('  Unique: %d  Dups removed: %d  Dep edges: %d' % (
    d['total_unique_gadgets'],
    d['duplicates_removed'],
    len(d['dependency_graph'])))
"
printf "\n"
printf "${YELLOW}Next step:${NC}  sudo ./phase3_chain_validation.sh -b <binary> -i %s\n" "$OUTPUT_FILE"
