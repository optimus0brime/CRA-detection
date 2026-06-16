#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — OPCODE COLLECTION  (Static Analysis)  [FIXED]
#  CRA Detection Framework | ELF x86_64 | POSIX sh
#
#  Pipeline: [phase1] --> phase1_gadget_catalog.json --> [phase2]
#
#  FIXES APPLIED:
#    FIX-1  identify_sink() rewritten as explicit if/elif chain.
#           Old code relied silently on dict insertion order; the CJMP
#           guard used `continue` which only skipped to the next dict entry,
#           making it dead code for any instruction already matched by an
#           earlier pattern.  Explicit re.match() calls ordered
#           ret -> jmp/jmpq -> conditional-jmp -> call are unambiguous.
#
#    FIX-2  `nop` removed from BOUND_PAT.
#           Compiler NOP padding (alignment, pipeline hints) appears inside
#           valid gadget bodies and should not terminate a backward walk.
#           Premature termination silently dropped chains shorter than
#           depth_min that were only short because of the NOP cut.
#
#    FIX-3  posix_realpath() applied to BINARY before the Python block.
#           Both the shell wrapper and the embedded Python now see the same
#           canonical path, making log paths and ldd output consistent when
#           the user passes a relative or symlinked path.
#
#    FIX-4  Sidecar metadata file (phase1_meta.json) written by Python.
#           The final stats line in the shell previously called
#           `json.load()` on the full catalog just to print total_gadgets,
#           loading up to hundreds of MB into a fresh interpreter.
#           The sidecar holds only {total_gadgets, sink_distribution} and
#           is read instead.
#
#  Usage:
#    ./phase1_opcode_collection.sh -b <binary> [options]
#
#  Options:
#    -b  Path to target ELF binary              (required)
#    -o  Output directory                       (default: ./cra_output)
#    -d  Minimum backward chain depth           (default: 5)
#    -D  Maximum backward chain depth           (default: 15)
#    -L  Also scan shared libraries: 1=yes 0=no (default: 1)
#    -G  Max total gadgets before stopping      (default: 100000)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

# ── Portable realpath ──────────────────────────────────────────────────────
posix_realpath() {
    if command -v realpath >/dev/null 2>&1; then
        realpath "$1"
    else
        readlink -f "$1" 2>/dev/null \
            || ( cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")" )
    fi
}

usage() {
    grep '^#' "$0" | sed 's/^# \{0,2\}//' | sed 's/^#//'
    exit 0
}

# ── Defaults ──────────────────────────────────────────────────────────────
BINARY=""
OUTPUT_DIR="./cra_output"
CHAIN_DEPTH_MIN=5
CHAIN_DEPTH_MAX=15
SCAN_LIBS=1
MAX_GADGETS=100000
PHASE0_REPORT=""

# Manual loop — POSIX getopts cannot handle --long-options.
# Supports:  -b <bin>  -o <dir>  -d N  -D N  -L 0|1  -G N
#            -p <path>  --phase0 <path>  -h / --help
while [ $# -gt 0 ]; do
    case "$1" in
        -b)       BINARY="$2";          shift 2 ;;
        -o)       OUTPUT_DIR="$2";      shift 2 ;;
        -d)       CHAIN_DEPTH_MIN="$2"; shift 2 ;;
        -D)       CHAIN_DEPTH_MAX="$2"; shift 2 ;;
        -L)       SCAN_LIBS="$2";       shift 2 ;;
        -G)       MAX_GADGETS="$2";     shift 2 ;;
        -p|--phase0) PHASE0_REPORT="$2"; shift 2 ;;
        -h|--help)   usage ;;
        -*) die "Unknown option: $1" ;;
        *)  die "Unexpected argument: $1" ;;
    esac
done

[ -z "$BINARY" ]   && die "No binary specified. Use -b <binary>"
[ ! -f "$BINARY" ] && die "Binary not found: $BINARY"

# FIX-3: resolve canonical path once; both shell and Python see the same path
BINARY_ABS=$(posix_realpath "$BINARY")

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 1: Opcode Collection${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"

log "Binary      : $BINARY_ABS"
log "Output dir  : $OUTPUT_DIR"
log "Chain depth : $CHAIN_DEPTH_MIN - $CHAIN_DEPTH_MAX instructions"
log "Scan libs   : $SCAN_LIBS"
log "Max gadgets : $MAX_GADGETS"
[ -n "$PHASE0_REPORT" ] && log "Phase 0 rpt : $PHASE0_REPORT (lib scope + base addresses)"
printf "\n"

# ── Tool checks ───────────────────────────────────────────────────────────
for _tool in objdump readelf ldd file python3; do
    command -v "$_tool" >/dev/null 2>&1 || die "Required tool not found: $_tool"
done

python3 -c "import capstone" 2>/dev/null \
    || die "Python capstone module missing. Run: pip install capstone"

# ── ELF verification (use canonical path) ─────────────────────────────────
FILE_INFO=$(file "$BINARY_ABS")
printf '%s\n' "$FILE_INFO" | grep -q "ELF 64-bit" \
    || die "Not an ELF 64-bit binary: $FILE_INFO"
printf '%s\n' "$FILE_INFO" | grep -q "x86-64\|AMD x86-64" \
    || warn "May not be x86-64 -- proceeding anyway"

mkdir -p "$OUTPUT_DIR"
CATALOG="$OUTPUT_DIR/phase1_gadget_catalog.json"
# FIX-4: sidecar path known to both Python and shell
SIDECAR="$OUTPUT_DIR/phase1_meta.json"

# ── Python analysis ───────────────────────────────────────────────────────
# FIX-3: pass BINARY_ABS (canonical) not raw $BINARY
python3 - "$BINARY_ABS" "$CATALOG" \
          "$CHAIN_DEPTH_MIN" "$CHAIN_DEPTH_MAX" \
          "$SCAN_LIBS" "$OUTPUT_DIR" "$MAX_GADGETS" \
          "${PHASE0_REPORT:-NONE}" \
<< 'PYEOF'
import sys, os, re, json, hashlib, subprocess, gc
from datetime import datetime

binary       = sys.argv[1]
output_path  = sys.argv[2]
depth_min    = int(sys.argv[3])
depth_max    = int(sys.argv[4])
scan_libs    = sys.argv[5] == "1"
output_dir   = sys.argv[6]
MAX_GADGETS  = int(sys.argv[7])
phase0_report= sys.argv[8] if sys.argv[8] != "NONE" else None

MAX_MAIN     = min(50000, MAX_GADGETS)
MAX_PER_LIB  = min(20000, MAX_GADGETS // 4)

JSONL_TMP = output_path + ".tmp.jsonl"

# ── Phase 0 integration: scope lib scanning + annotate base addresses ─────
# If a phase0_vuln_report.json is provided, Phase 1 uses its memory_map to:
#   (a) restrict shared-lib scanning to only libs actually loaded at crash time
#       — avoids wasting time on libs the vulnerable code path never touches
#   (b) record the runtime base address of each lib (from the crash maps) so
#       Phase 3 can resolve gadget addresses without re-running the binary
p0_mapped_libs    = set()   # abs paths of libs in crash memory map
p0_base_addresses = {}      # lib_path -> runtime base (hex str)
p0_controlled_regs= []      # regs attacker controlled at crash

if phase0_report:
    try:
        with open(phase0_report) as fh:
            p0 = json.load(fh)
        for m in p0.get("all_memory_maps", []):
            path = m.get("path","").strip()
            if path and path.startswith("/") and ".so" in path:
                p0_mapped_libs.add(path)
                if path not in p0_base_addresses:
                    p0_base_addresses[path] = m.get("start","0x0")
        p0_controlled_regs = p0.get("all_controlled_registers", [])
        print("  [*] Phase 0 report loaded: %d mapped libs  %d ctrl regs"
              % (len(p0_mapped_libs), len(p0_controlled_regs)))
    except Exception as exc:
        print("  [!] Could not load Phase 0 report (%s) — scanning all libs" % exc)

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

RAM_WARN_MB  = 4000
RAM_ABORT_MB = 5500

def check_ram(label=""):
    used = mem_mb()
    if used > RAM_ABORT_MB:
        print("  [!] RAM abort at %s (%d MB) -- stopping" % (label, used),
              file=sys.stderr)
        sys.exit(1)
    if used > RAM_WARN_MB:
        print("  [!] High RAM at %s: %d MB -- running gc" % (label, used))
        gc.collect()
    return used

# ── FIX-1: Sink identification — explicit if/elif, ordered ret→jmp→cjmp→call
# Old code used a dict of compiled patterns and relied on insertion order to
# ensure JMP was tested before CJMP.  The CJMP guard used `continue` which
# only advances the for-loop over SINK_PAT entries — it cannot return None
# from the outer function.  The new version uses re.match() with anchored
# patterns and an unambiguous priority chain.
def identify_sink(instr):
    s = instr.strip()
    # RET family: ret, retq, ret 0xN
    if re.match(r'^ret[q]?\s*(?:0x[0-9a-f]+)?\s*$', s, re.IGNORECASE):
        return "RET"
    # Unconditional JMP — must be checked before the j[a-z]{1,5} CJMP pattern
    if re.match(r'^(?:jmp|jmpq)\s+', s, re.IGNORECASE):
        return "JMP"
    # Conditional JMP — all other j* mnemonics (ja, jb, je, jne, jge, …)
    if re.match(r'^j[a-z]{1,5}\s+', s, re.IGNORECASE):
        return "CJMP"
    # CALL family
    if re.match(r'^(?:call|callq)\s+', s, re.IGNORECASE):
        return "CALL"
    return None

# ── FIX-2: Boundary markers — nop removed
# `nop` (and alignment variants) appear as compiler padding inside function
# bodies and do NOT mark a function prologue or memory barrier.  Including
# them caused the backward walk to terminate early, silently dropping any
# chain that crossed a padding NOP.
BOUND_PAT = [
    re.compile(r"\bpush\s+%?rbp\b",            re.IGNORECASE),
    re.compile(r"\bmov\s+%?rsp\s*,\s*%?rbp\b", re.IGNORECASE),
    re.compile(r"\bendbr64\b",                  re.IGNORECASE),
    re.compile(r"\blfence\b",                   re.IGNORECASE),
    re.compile(r"\bmfence\b",                   re.IGNORECASE),
    re.compile(r"\bsfence\b",                   re.IGNORECASE),
    re.compile(r"\bint3\b",                     re.IGNORECASE),
    # nop intentionally omitted — see FIX-2 above
]

def is_boundary(instr):
    return any(p.search(instr) for p in BOUND_PAT)

# ── Disassembly ───────────────────────────────────────────────────────────
def disassemble(target):
    try:
        r = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", target],
            capture_output=True, text=True, timeout=180,
        )
        return r.stdout
    except Exception as exc:
        print("  [!] objdump failed for %s: %s" % (target, exc), file=sys.stderr)
        return ""

def parse_objdump(asm_text):
    rows = []
    func_name = "unknown"
    for line in asm_text.splitlines():
        fm = re.match(r"^([0-9a-f]+)\s+<([^>]+)>:", line)
        if fm:
            func_name = fm.group(2)
            continue
        im = re.match(r"^\s+([0-9a-f]+):\s+(.+)", line)
        if im:
            addr  = int(im.group(1), 16)
            instr = re.sub(r"^([0-9a-f]{2}\s+)+", "", im.group(2).strip()).strip()
            rows.append((addr, instr, func_name))
    return rows

# ── Core: stream gadgets straight to an open file handle ─────────────────
def stream_gadgets(asm_text, source_file, out_fh,
                   start_id, cap, seen_hashes, sink_dist):
    instructions = parse_objdump(asm_text)
    written = 0
    n = len(instructions)

    for i in range(n):
        if written >= cap:
            print("  [!] Cap %d reached for %s -- moving on"
                  % (cap, source_file), file=sys.stderr)
            break

        addr, instr, func = instructions[i]
        sink_type = identify_sink(instr)
        if not sink_type:
            continue

        chain = []
        for depth in range(1, depth_max + 1):
            j = i - depth
            if j < 0:
                break
            p_addr, p_instr, _ = instructions[j]
            if is_boundary(p_instr):
                break
            if identify_sink(p_instr) is not None:
                break
            chain.insert(0, {"address": hex(p_addr), "mnemonic": p_instr})

        if len(chain) < depth_min - 1:
            continue

        full_chain = chain + [{"address": hex(addr), "mnemonic": instr}]
        chain_text = "|".join(c["mnemonic"] for c in full_chain)
        chain_hash = hashlib.md5(chain_text.encode()).hexdigest()[:16]

        if chain_hash in seen_hashes:
            continue
        seen_hashes.add(chain_hash)

        gadget = {
            "gadget_id":        "G%06d" % (start_id + written),
            "hash":             chain_hash,
            "sink_address":     hex(addr),
            "sink_type":        sink_type,
            "sink_instruction": instr,
            "function":         func,
            "source_binary":    source_file,
            "chain_length":     len(full_chain),
            "instructions":     full_chain,
        }
        out_fh.write(json.dumps(gadget, separators=(",", ":")) + "\n")
        sink_dist[sink_type] = sink_dist.get(sink_type, 0) + 1
        written += 1

    del instructions
    return written

# ── Shared library discovery ──────────────────────────────────────────────
def get_shared_libs(binary_path):
    libs = []
    try:
        out = subprocess.check_output(
            ["ldd", binary_path], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            m = re.search(r"=>\s+(/\S+\.so\S*)", line)
            if m and os.path.isfile(m.group(1)):
                libs.append(m.group(1))
    except Exception:
        pass
    return libs

# ── Final JSON assembly ────────────────────────────────────────────────────
def assemble_json(jsonl_path, output_path, metadata):
    with open(output_path, "w") as out:
        out.write("{\n")
        for k, v in metadata.items():
            out.write("  %s: %s,\n" % (json.dumps(k), json.dumps(v)))
        out.write('  "gadgets": [\n')
        first = True
        with open(jsonl_path) as src:
            for line in src:
                line = line.strip()
                if not line:
                    continue
                if not first:
                    out.write(",\n")
                out.write("    " + line)
                first = False
        out.write("\n  ]\n}\n")

# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════
seen_hashes = set()
sink_dist   = {}
total       = 0

with open(JSONL_TMP, "w") as tmp_fh:

    print("  [*] Disassembling: %s" % binary)
    asm = disassemble(binary)
    check_ram("after main disassemble")
    written = stream_gadgets(asm, binary, tmp_fh,
                             start_id=0, cap=MAX_MAIN,
                             seen_hashes=seen_hashes, sink_dist=sink_dist)
    total += written
    del asm
    gc.collect()
    print("  [+] Gadgets from main binary : %d  (RAM: %d MB)" % (written, mem_mb()))

    if scan_libs and total < MAX_GADGETS:
        libs = get_shared_libs(binary)

        # Phase 0 integration: if we have a crash memory map, only scan libs
        # that were actually loaded at crash time.  Unrelated libs produce
        # gadgets the exploit can never reach through the vulnerable code path.
        if p0_mapped_libs:
            original_count = len(libs)
            libs = [l for l in libs if l in p0_mapped_libs]
            skipped = original_count - len(libs)
            if skipped:
                print("  [*] Phase 0 scope filter: skipped %d libs not in crash map"
                      % skipped)

        print("  [*] Shared libraries to scan : %d" % len(libs))

        for lib in libs:
            if total >= MAX_GADGETS:
                print("  [!] Global cap %d reached -- skipping remaining libs"
                      % MAX_GADGETS, file=sys.stderr)
                break
            check_ram("before lib")

            cap_lib = min(MAX_PER_LIB, MAX_GADGETS - total)
            print("      -> %s  (cap: %d)" % (lib, cap_lib))
            lib_asm = disassemble(lib)
            lib_n   = stream_gadgets(lib_asm, lib, tmp_fh,
                                     start_id=total, cap=cap_lib,
                                     seen_hashes=seen_hashes, sink_dist=sink_dist)
            total += lib_n
            del lib_asm
            gc.collect()
            print("         gadgets: %d  running total: %d  RAM: %d MB"
                  % (lib_n, total, mem_mb()))

print("  [*] Assembling final catalog (%d gadgets) ..." % total)
metadata = {
    "phase":             1,
    "binary":            binary,
    "generated_at":      datetime.utcnow().isoformat() + "Z",
    "chain_depth_range": [depth_min, depth_max],
    "total_gadgets":     total,
    "sink_distribution": sink_dist,
    "phase0_report":     phase0_report or "",
    "phase0_controlled_registers": p0_controlled_regs,
    "phase0_base_addresses":       p0_base_addresses,
}
assemble_json(JSONL_TMP, output_path, metadata)
os.unlink(JSONL_TMP)

# FIX-4: write lightweight sidecar so the shell stats line does not need to
#         load the full catalog (which can be hundreds of MB) just to print
#         one integer.
sidecar_path = os.path.join(output_dir, "phase1_meta.json")
with open(sidecar_path, "w") as mf:
    json.dump({"total_gadgets": total, "sink_distribution": sink_dist}, mf)

print("  [+] Sink breakdown : %s" % str(sink_dist))
print("  [+] Catalog written: %s  (RSS: %d MB)" % (output_path, mem_mb()))
print("  [+] Sidecar written: %s" % sidecar_path)
PYEOF

printf "\n"
ok "Phase 1 complete -> $CATALOG"
# FIX-4: read stats from sidecar, not from the full catalog
ok "Total gadgets: $(python3 -c "import json; d=json.load(open('$SIDECAR')); print(d['total_gadgets'])")"
printf "\n"
printf "${YELLOW}Next step:${NC}  ./phase2_gadget_identification.sh -i %s\n" "$CATALOG"
