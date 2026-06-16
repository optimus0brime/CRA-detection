#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 0 — VULNERABILITY DETECTION  (Enhanced Static + Dynamic)
#  CRA Detection Framework | ELF x86-64 / Multi-arch | POSIX sh
#
#  Pipeline outputs:
#    phase0_vuln_report.json           machine-readable  → phases 1-4
#    phase0_disassembly_report.md      Phase 0  human report
#    phase0_5_vulnerability_report.md  Phase 0.5 classification report
#    phase0_handoff_summary.md         one-page executive brief → phases 1-4
#    phase0_crashes/                   unique AFL++ crash inputs
#
#  Two-stage architecture:
#    ┌─ Stage A: Static Analysis (always runs — finds vulns without crashes) ─┐
#    │  S1  Binary metadata     format · arch · type · build flags            │
#    │  S2  Section mapping     .text .data .rodata .bss .got.plt etc.        │
#    │  S3  Function analysis   signatures · stack frames · call graphs       │
#    │  S4  Pattern detection   dangerous funcs · buffer ops · syscalls       │
#    │  S5  Classification      Phase 0.5 structured vulnerability catalog    │
#    │  S6  Offset computation  analytical RIP offset — no crash needed       │
#    │  S7  Hand-off report     addresses · PoC data · exploitation order     │
#    └───────────────────────────────────────────────────────────────────────┘
#    ┌─ Stage B: Dynamic Analysis (optional — AFL++ + GDB confirmation) ─────┐
#    │  S8  Targeted seeds      overflow seeds tuned from Stage A findings    │
#    │  S9  AFL++ fuzzing       input mode auto-detected from Stage A         │
#    │  S10 Crash triage        GDB · cyclic offset · register state         │
#    │  S11 Final merge         static + dynamic findings → unified JSON      │
#    └───────────────────────────────────────────────────────────────────────┘
#
#  Vulnerability classes detected:
#    Buffer Overflow (stack + heap)   Format String    Use-After-Free
#    Integer Overflow                 Command Injection Null Ptr Deref
#    Information Disclosure           Logic Flaw        Race Condition
#    GOT Overwrite (Partial RELRO)    Executable Stack  Missing Canary
#
#  Input modes (-i flag):
#    file   — binary reads from argv[1]           (default)
#    stdin  — binary reads from stdin             (auto-detected if gets/scanf)
#    arg    — crash content passed as argv token
#
#  Tool dependencies:
#    Required  : python3, objdump, readelf, nm, file, strings
#    Pwntools  : pip install pwntools  (offset probing)
#    Optional  : afl-fuzz (Stage B), gdb (Stage B), checksec, checksec.sh
#                afl-tmin (crash minimisation)
#
#  Usage:
#    ./phase0_vuln_detection.sh -b <binary> [options]
#
#  Options:
#    -b  Target binary path                    (required)
#    -o  Output directory                      (default: ./cra_output)
#    -s  Seed corpus directory                 (default: auto-generated)
#    -t  AFL++ fuzz duration (seconds)         (default: 300)
#    -c  Pre-existing crash corpus (skip fuzz) (default: none)
#    -i  Input mode: file | stdin | arg        (default: auto)
#    -m  AFL++ memory limit MB                 (default: 200)
#    -j  AFL++ parallel jobs                   (default: 1)
#    -A  ASan-instrumented binary path         (default: none)
#    -S  Skip Stage B (static-only mode)       (default: 0)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';   NC='\033[0m'
MAGENTA='\033[0;35m'

log()   { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()    { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }
step()  { printf "\n${BOLD}── %s${NC}\n" "$*"; }
vuln()  { printf "${MAGENTA}[VULN]${NC} %s\n" "$*"; }

posix_realpath() {
    if command -v realpath >/dev/null 2>&1; then realpath "$1"
    else readlink -f "$1" 2>/dev/null \
        || ( cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")" )
    fi
}
usage() { grep '^#' "$0" | sed 's/^# \{0,2\}//' | sed 's/^#//'; exit 0; }

# ── Defaults ──────────────────────────────────────────────────────────────
BINARY=""
OUTPUT_DIR="./cra_output"
SEED_DIR=""
FUZZ_TIMEOUT=300
CRASH_CORPUS=""
INPUT_MODE="auto"
MEM_LIMIT=200
AFL_JOBS=1
ASAN_BINARY=""
SKIP_DYNAMIC=0

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BINARY="$2";        shift 2 ;;
        -o) OUTPUT_DIR="$2";    shift 2 ;;
        -s) SEED_DIR="$2";      shift 2 ;;
        -t) FUZZ_TIMEOUT="$2";  shift 2 ;;
        -c) CRASH_CORPUS="$2";  shift 2 ;;
        -i) INPUT_MODE="$2";    shift 2 ;;
        -m) MEM_LIMIT="$2";     shift 2 ;;
        -j) AFL_JOBS="$2";      shift 2 ;;
        -A) ASAN_BINARY="$2";   shift 2 ;;
        -S) SKIP_DYNAMIC="$2";  shift 2 ;;
        -h|--help) usage ;;
        -*) die "Unknown option: $1" ;;
        *)  die "Unexpected argument: $1" ;;
    esac
done

[ -z "$BINARY" ]   && die "No binary specified. Use -b <binary>"
[ ! -f "$BINARY" ] && die "Binary not found: $BINARY"

case "$INPUT_MODE" in
    file|stdin|arg|auto) ;;
    *) die "Invalid input mode '$INPUT_MODE'. Use: file | stdin | arg | auto" ;;
esac

BINARY_ABS=$(posix_realpath "$BINARY")
BINARY_NAME=$(basename "$BINARY_ABS")
mkdir -p "$OUTPUT_DIR"

AFL_OUT="$OUTPUT_DIR/afl_output"
CRASH_DIR="$OUTPUT_DIR/phase0_crashes"
REPORT_JSON="$OUTPUT_DIR/phase0_vuln_report.json"
STATIC_JSON="$OUTPUT_DIR/phase0_static.json"
DISASM_MD="$OUTPUT_DIR/phase0_disassembly_report.md"
CLASS_MD="$OUTPUT_DIR/phase0_5_vulnerability_report.md"
HANDOFF_MD="$OUTPUT_DIR/phase0_handoff_summary.md"

mkdir -p "$AFL_OUT" "$CRASH_DIR"

printf "\n${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection — Phase 0: Vulnerability Detection${NC}\n"
printf "${BOLD}  Stage A: Static  |  Stage B: Dynamic (AFL++ + GDB)${NC}\n"
printf "${BOLD}%s${NC}\n\n" "======================================================="
log "Binary     : $BINARY_ABS"
log "Input mode : $INPUT_MODE"
log "Output dir : $OUTPUT_DIR"
[ -n "$CRASH_CORPUS" ] && log "Crash dir  : $CRASH_CORPUS (skip-fuzz mode)"
[ -n "$ASAN_BINARY"  ] && log "ASan binary: $ASAN_BINARY"
printf "\n"

# ── Tool checks ───────────────────────────────────────────────────────────
for _t in objdump readelf nm file strings python3; do
    command -v "$_t" >/dev/null 2>&1 || die "Required tool not found: $_t"
done

HAVE_AFL=false; command -v afl-fuzz >/dev/null 2>&1 && HAVE_AFL=true
HAVE_GDB=false; command -v gdb     >/dev/null 2>&1 && HAVE_GDB=true
HAVE_PWN=false
python3 -c "from pwn import cyclic, cyclic_find" 2>/dev/null && HAVE_PWN=true

log "afl-fuzz : $HAVE_AFL  |  gdb : $HAVE_GDB  |  pwntools : $HAVE_PWN"

file "$BINARY_ABS" | grep -q "ELF" || die "Not an ELF binary: $BINARY_ABS"

# ══════════════════════════════════════════════════════════════════════════
#  STAGE A — STEP 1: Static Analysis  (Phase 0 + Phase 0.5)
# ══════════════════════════════════════════════════════════════════════════
step "Stage A · Step 1-7: Static Analysis, Classification, Reports"

python3 - "$BINARY_ABS" "$OUTPUT_DIR" "$STATIC_JSON" \
           "$DISASM_MD" "$CLASS_MD" "$HANDOFF_MD" \
<< 'PYEOF'
import sys, os, re, json, subprocess, hashlib
from datetime import datetime, timezone
from collections import defaultdict

binary      = sys.argv[1]
output_dir  = sys.argv[2]
static_json = sys.argv[3]
disasm_md   = sys.argv[4]
class_md    = sys.argv[5]
handoff_md  = sys.argv[6]

# ── Constants ─────────────────────────────────────────────────────────────
DANGEROUS_FUNCS = {
    # Unbounded stdin reads — CRITICAL (removed from C11)
    "gets":     {"type":"STACK_BUFFER_OVERFLOW","severity":"CRITICAL",
                 "input_hint":"stdin","cwe":"CWE-121",
                 "reason":"gets() performs unbounded stdin read; no length param; C11-removed"},
    # Unbounded string ops
    "strcpy":   {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"arg","cwe":"CWE-121",
                 "reason":"strcpy() copies until NUL with no destination size check"},
    "strcat":   {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"arg","cwe":"CWE-121",
                 "reason":"strcat() appends without destination size check"},
    "sprintf":  {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"arg","cwe":"CWE-121",
                 "reason":"sprintf() writes formatted output without output buffer size"},
    "vsprintf": {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"arg","cwe":"CWE-121",
                 "reason":"vsprintf() is the variadic equivalent of sprintf — same issue"},
    "scanf":    {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"stdin","cwe":"CWE-121",
                 "reason":"scanf %s reads until whitespace with no width limit"},
    "fscanf":   {"type":"STACK_BUFFER_OVERFLOW","severity":"HIGH",
                 "input_hint":"file","cwe":"CWE-121",
                 "reason":"fscanf %s reads from FILE* without width limit"},
    # Potentially unsafe if size is unchecked
    "memcpy":   {"type":"STACK_BUFFER_OVERFLOW","severity":"MEDIUM",
                 "input_hint":"any","cwe":"CWE-120",
                 "reason":"memcpy() trusts caller-supplied length; integer overflow in size param"},
    "memmove":  {"type":"STACK_BUFFER_OVERFLOW","severity":"MEDIUM",
                 "input_hint":"any","cwe":"CWE-120",
                 "reason":"memmove() trusts caller-supplied length"},
    "strncpy":  {"type":"STACK_BUFFER_OVERFLOW","severity":"LOW",
                 "input_hint":"any","cwe":"CWE-120",
                 "reason":"strncpy() may omit NUL terminator; off-by-one possible"},
    # Shell spawners — command injection if arg is user-controlled
    "system":   {"type":"COMMAND_INJECTION","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-78",
                 "reason":"system() passes argument to /bin/sh -c; user input = RCE"},
    "popen":    {"type":"COMMAND_INJECTION","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-78",
                 "reason":"popen() passes argument to shell; user input = RCE"},
    "execl":    {"type":"COMMAND_INJECTION","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-78",
                 "reason":"execl() executes program; unvalidated path = code execution"},
    "execve":   {"type":"COMMAND_INJECTION","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-78",
                 "reason":"execve() direct program exec; unvalidated arg = RCE"},
    "execvp":   {"type":"COMMAND_INJECTION","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-78",
                 "reason":"execvp() searches PATH; unvalidated name = RCE"},
    # Format string — only a vuln if format arg is non-const
    "printf":   {"type":"FORMAT_STRING","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-134",
                 "reason":"printf(user_str) — if first arg is user-controlled, arbitrary read/write"},
    "fprintf":  {"type":"FORMAT_STRING","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-134",
                 "reason":"fprintf format string if non-const = arbitrary read/write"},
    "syslog":   {"type":"FORMAT_STRING","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-134",
                 "reason":"syslog format string if non-const = info disclosure"},
    # Memory management
    "free":     {"type":"USE_AFTER_FREE","severity":"HIGH",
                 "input_hint":"any","cwe":"CWE-416",
                 "reason":"free() without null-assignment; subsequent dereference = UAF"},
    "malloc":   {"type":"INTEGER_OVERFLOW","severity":"MEDIUM",
                 "input_hint":"any","cwe":"CWE-190",
                 "reason":"malloc(user_size) without overflow check; size wraps to small alloc"},
    "realloc":  {"type":"INTEGER_OVERFLOW","severity":"MEDIUM",
                 "input_hint":"any","cwe":"CWE-190",
                 "reason":"realloc size calculation may overflow"},
    "calloc":   {"type":"INTEGER_OVERFLOW","severity":"MEDIUM",
                 "input_hint":"any","cwe":"CWE-190",
                 "reason":"calloc(n, size) — n×size can overflow on 32-bit targets"},
}

SHELL_SPAWNERS = {"system","execve","execl","execvp","execlp","execle","popen"}

SEV_ORDER = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}

# ── Subprocess helper ─────────────────────────────────────────────────────
def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.stdout
    except Exception:
        return ""

# ── Binary metadata ───────────────────────────────────────────────────────
def get_metadata(binary):
    meta = {
        "file_info": run(["file", binary]).strip(),
        "arch":      "unknown",
        "bits":      64,
        "type":      "ELF",
        "pie":       False,
        "canary":    False,
        "nx":        True,
        "relro":     "none",
        "stripped":  True,
        "build_id":  "",
        "compiler":  "",
        "interp":    "",
        "aslr_level":2,
    }
    fi = meta["file_info"].lower()
    if "x86-64" in fi or "amd64" in fi:        meta["arch"] = "x86-64"
    elif "arm" in fi and "64" in fi:            meta["arch"] = "AArch64"
    elif "arm" in fi:                           meta["arch"] = "ARM"
    elif "386" in fi or "i386" in fi:           meta["arch"] = "x86"
    elif "mips" in fi:                          meta["arch"] = "MIPS"
    if "32-bit" in fi:                          meta["bits"] = 32

    # checksec-equivalent via readelf
    sec_out = run(["readelf", "-W", "-S", binary])
    gnu_stack_m = re.search(r'GNU_STACK.*?(R\w*)', sec_out)
    if gnu_stack_m:
        flags = gnu_stack_m.group(1)
        meta["nx"] = "E" not in flags

    dyn_out = run(["readelf", "-d", binary])
    if "BIND_NOW" in dyn_out:             meta["relro"] = "full"
    elif "RELRO" in run(["readelf","-W","-S",binary]): meta["relro"] = "partial"

    # PIE check
    elf_hdr = run(["readelf", "-h", binary])
    if "DYN" in elf_hdr:                  meta["pie"] = True

    # Canary — presence of __stack_chk_fail in dynamic symbols
    dyn_syms = run(["nm", "-D", binary])
    meta["canary"] = "__stack_chk_fail" in dyn_syms

    # Build-ID
    bid_m = re.search(r'Build ID:\s*([0-9a-f]+)', run(["readelf","-n",binary]))
    if bid_m: meta["build_id"] = bid_m.group(1)

    # Stripped?
    symtab_out = run(["readelf","-s",binary])
    meta["stripped"] = ".symtab" not in run(["readelf","-S",binary])

    # Try /proc/sys/kernel/randomize_va_space
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            meta["aslr_level"] = int(f.read().strip())
    except Exception:
        pass

    return meta

# ── Section enumeration ───────────────────────────────────────────────────
def get_sections(binary):
    out = run(["readelf","-W","-S",binary])
    sections = []
    for line in out.splitlines():
        m = re.match(
            r'\s+\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+[0-9a-f]+\s+(\w*)',
            line)
        if m:
            name, addr_s, size_s, flags = m.groups()
            if name and name != "NULL" and name != "":
                sections.append({
                    "name":  name,
                    "addr":  "0x" + addr_s.lstrip("0") if addr_s != "0"*len(addr_s) else "0x0",
                    "size":  int(size_s, 16),
                    "flags": flags,
                })
    return sections

# ── Symbol table ──────────────────────────────────────────────────────────
def get_symbols(binary):
    static_syms, dynamic_syms = {}, {}
    # Static (.symtab)
    for line in run(["readelf","-s","--wide",binary]).splitlines():
        m = re.match(r'\s+\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+\w+\s+\w+\s+\S+\s+(\S+)', line)
        if m:
            addr, size, stype, name = m.groups()
            if stype == "FUNC" and name not in ("","UND","*UND*"):
                static_syms[name] = {"addr": int(addr,16), "size": int(size)}
    # Dynamic (.dynsym)
    for line in run(["nm","-D",binary]).splitlines():
        m = re.match(r'([0-9a-f]+)?\s+\w\s+(.+)', line)
        if m:
            addr_s, name = m.group(1), m.group(2).strip().split("@")[0]
            dynamic_syms[name] = int(addr_s, 16) if addr_s else 0
    return static_syms, dynamic_syms

# ── PLT map ───────────────────────────────────────────────────────────────
def get_plt_map(binary):
    """Map function name → PLT address from disassembly."""
    out = run(["objdump","-d","-M","intel",binary])
    plt = {}
    current_fn = None
    current_addr = None
    for line in out.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+<(.+?)(?:@plt)?>:', line)
        if m:
            current_addr = int(m.group(1), 16)
            current_fn = m.group(2).strip()
            if "@" not in m.group(2) and current_fn not in plt:
                plt[current_fn] = current_addr
    return plt

# ── Disassembly parser ────────────────────────────────────────────────────
def disassemble(binary):
    return run(["objdump","-d","-M","intel","--no-show-raw-insn",binary], timeout=120)

def parse_asm(asm_text):
    """Returns dict: func_name → list of (addr_int, mnemonic_str)."""
    funcs = {}
    current = None
    for line in asm_text.splitlines():
        fm = re.match(r'^([0-9a-f]+)\s+<(.+?)>:', line)
        if fm:
            current = fm.group(2).strip()
            funcs[current] = []
            continue
        im = re.match(r'^\s+([0-9a-f]+):\s+(.+)', line)
        if im and current:
            raw = im.group(2).strip()
            ins = re.sub(r'^([0-9a-f]{2}\s+)+', '', raw).strip()
            funcs[current].append((int(im.group(1), 16), ins))
    return funcs

# ── Function analysis ─────────────────────────────────────────────────────
def analyze_function(name, instructions):
    """
    Returns dict:
      frame_size, regs_used, calls, dangerous_calls,
      buffers (list of {offset_rbp, lea_addr}),
      instructions_text (list of formatted strings)
    """
    frame_size = 0
    regs = set()
    calls = []
    dangerous = []
    buffers = []
    ins_text = []

    for addr, mnem in instructions:
        ins_text.append(f"  {addr:#010x}:  {mnem}")
        # Registers
        for r in re.findall(r'\b(r[a-z0-9]+|e[a-z]{2}|[a-z]{2})\b', mnem):
            if r in {'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
                     'r8','r9','r10','r11','r12','r13','r14','r15',
                     'eax','ebx','ecx','edx','esi','edi','ebp','esp'}:
                regs.add(r)
        # Frame size from sub rsp / sub esp
        m = re.match(r'sub\s+[re]sp,\s*(0x[0-9a-f]+|\d+)', mnem, re.I)
        if m:
            v = m.group(1)
            frame_size = int(v,16) if v.startswith('0x') else int(v)
        # Buffer definitions via lea [rbp-N]
        m = re.match(r'lea\s+\w+,\s*\[rbp\s*-\s*(0x[0-9a-f]+|\d+)\]', mnem, re.I)
        if m:
            v = m.group(1)
            buf_offset = int(v,16) if v.startswith('0x') else int(v)
            buffers.append({"offset_from_rbp": buf_offset, "lea_addr": addr})
        # Calls
        cm = re.match(r'call\s+(?:0x[0-9a-f]+\s+)?<(.+?)(?:@plt)?>?', mnem, re.I)
        if cm:
            called = cm.group(1).split("@")[0].strip()
            calls.append({"name": called, "call_addr": addr})
            if called in DANGEROUS_FUNCS:
                # Identify buffer argument (look back for last lea + mov rdi)
                prior = [(a2, m2) for a2, m2 in instructions if a2 < addr][-12:]
                buf_sz = None
                for pa, pm in reversed(prior):
                    lm = re.match(r'lea\s+\w+,\s*\[rbp\s*-\s*(0x[0-9a-f]+|\d+)\]', pm, re.I)
                    if lm:
                        v = lm.group(1)
                        buf_sz = int(v,16) if v.startswith('0x') else int(v)
                        break
                rip_offset = (buf_sz + 8) if buf_sz else (frame_size + 8 if frame_size else None)
                dangerous.append({
                    "call_addr":    addr,
                    "func_name":    called,
                    "buf_size":     buf_sz,
                    "frame_size":   frame_size,
                    "rip_offset":   rip_offset,
                    **DANGEROUS_FUNCS[called],
                })

    return {
        "frame_size":        frame_size,
        "regs_used":         sorted(regs),
        "calls":             calls,
        "dangerous_calls":   dangerous,
        "buffers":           buffers,
        "instructions_text": ins_text,
    }

# ── Win function detection ────────────────────────────────────────────────
def find_win_functions(func_analyses, plt_map):
    """
    A win function is one that calls a shell spawner with a CONSTANT argument
    and is not the main program entry (i.e., reachable via return hijack).
    """
    wins = []
    for fname, analysis in func_analyses.items():
        if fname in {"main","_start","__libc_start_main"}: continue
        for call in analysis["calls"]:
            if call["name"] in SHELL_SPAWNERS:
                # Check if RDI is a constant immediately before the call
                ins_list = analysis.get("instructions_text", [])
                call_addr = call["call_addr"]
                const_arg = False
                for line in ins_list:
                    # mov edi/rdi, immediate (constant string ptr)
                    if re.search(r'mov\s+[er]?di,\s+0x[0-9a-f]+', line, re.I):
                        const_arg = True
                wins.append({
                    "function": fname,
                    "spawner":  call["name"],
                    "call_addr": call["call_addr"],
                    "const_arg": const_arg,
                })
    return wins

# ── Strings extraction ────────────────────────────────────────────────────
def get_rodata_strings(binary):
    """Extract strings from binary, try to get addresses."""
    out = run(["strings", "-a", "-t", "x", binary])
    strings = []
    for line in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+)\s+(.*)', line)
        if m and len(m.group(2)) >= 3:
            strings.append({"offset": int(m.group(1),16), "value": m.group(2)})
    return strings[:80]  # cap at 80

# ── Suspicious pattern scanner ────────────────────────────────────────────
def scan_patterns(binary, func_analyses, meta, sections, plt_syms):
    """
    High-level pattern scanner that produces a flat list of findings
    for Phase 0.5 classification.
    """
    patterns = []
    pid = 1

    # 1. Dangerous function calls
    for fname, analysis in func_analyses.items():
        for dc in analysis["dangerous_calls"]:
            # For format string functions: check if first arg is a variable
            is_fmt_vuln = False
            if dc["func_name"] in {"printf","fprintf","syslog"}:
                # Scan backwards — if first arg (rdi/rsi for fprintf) is not an immediate
                # look for the presence of a user-tainted variable
                # Simplified heuristic: if there is NO const string setup before the call
                prior_ins = [i for i in analysis["instructions_text"]
                             if f"{dc['call_addr']:#010x}" not in i][-8:]
                has_const_fmt = any(
                    re.search(r'mov\s+[er]?di,\s+0x[0-9a-f]+', l, re.I)
                    for l in prior_ins
                )
                is_fmt_vuln = not has_const_fmt
                if not is_fmt_vuln:
                    continue  # format is a const — not a vulnerability

            patterns.append({
                "id":           f"P{pid:03d}",
                "call_addr":    dc["call_addr"],
                "func_name":    dc["func_name"],
                "in_function":  fname,
                "type":         dc["type"],
                "severity":     dc["severity"],
                "cwe":          dc["cwe"],
                "reason":       dc["reason"],
                "buf_size":     dc.get("buf_size"),
                "frame_size":   dc.get("frame_size"),
                "rip_offset":   dc.get("rip_offset"),
                "input_hint":   dc.get("input_hint","any"),
                "confidence":   "HIGH",
            })
            pid += 1

    # 2. Executable stack
    if not meta["nx"]:
        patterns.append({
            "id": f"P{pid:03d}", "call_addr": None, "func_name": "GNU_STACK",
            "in_function": "[binary-wide]",
            "type": "EXECUTABLE_STACK", "severity": "HIGH",
            "cwe": "CWE-693",
            "reason": "GNU_STACK ELF segment has PF_X set; stack/heap memory is executable",
            "buf_size": None, "frame_size": None, "rip_offset": None,
            "input_hint": "any", "confidence": "HIGH",
        })
        pid += 1

    # 3. Writable GOT (Partial RELRO)
    if meta["relro"] in ("partial", "none"):
        got_sec = next((s for s in sections if ".got.plt" in s["name"]), None)
        if got_sec:
            patterns.append({
                "id": f"P{pid:03d}", "call_addr": int(got_sec["addr"],16),
                "func_name": ".got.plt",
                "in_function": "[binary-wide]",
                "type": "WRITABLE_GOT", "severity": "MEDIUM",
                "cwe": "CWE-119",
                "reason": ("Partial RELRO: .got.plt at " + got_sec["addr"] +
                           " is writable at runtime; arbitrary write → GOT overwrite → code exec"),
                "buf_size": got_sec["size"], "frame_size": None, "rip_offset": None,
                "input_hint": "any", "confidence": "HIGH",
                "got_addr": got_sec["addr"], "got_size": got_sec["size"],
            })
            pid += 1

    # 4. Missing stack canary
    if not meta["canary"]:
        bof_found = any(p["type"] == "STACK_BUFFER_OVERFLOW" for p in patterns)
        if bof_found:
            patterns.append({
                "id": f"P{pid:03d}", "call_addr": None, "func_name": "__stack_chk_fail",
                "in_function": "[binary-wide]",
                "type": "MISSING_STACK_CANARY", "severity": "HIGH",
                "cwe": "CWE-693",
                "reason": "__stack_chk_fail absent; stack overflows execute silently with no abort",
                "buf_size": None, "frame_size": None, "rip_offset": None,
                "input_hint": "any", "confidence": "HIGH",
            })
            pid += 1

    # 5. Information disclosure via address leak
    for fname, analysis in func_analyses.items():
        for ins_line in analysis.get("instructions_text", []):
            # printf("...%p...", func_addr)
            if re.search(r'%p', ins_line) and re.search(r'call.*printf', ins_line, re.I):
                addr_m = re.match(r'\s*(0x[0-9a-f]+):', ins_line)
                if addr_m:
                    patterns.append({
                        "id": f"P{pid:03d}",
                        "call_addr": int(addr_m.group(1),16),
                        "func_name": "printf", "in_function": fname,
                        "type": "INFORMATION_DISCLOSURE", "severity": "LOW",
                        "cwe": "CWE-200",
                        "reason": "printf with %%p format prints a memory address to stdout",
                        "buf_size": None, "frame_size": None, "rip_offset": None,
                        "input_hint": "none", "confidence": "HIGH",
                    })
                    pid += 1
                    break  # one per function

    return patterns

# ──────────────────────────────────────────────────────────────────────────
#  MAIN ANALYSIS FLOW
# ──────────────────────────────────────────────────────────────────────────
print("  [*] Extracting binary metadata...")
meta = get_metadata(binary)
print(f"  [*] Arch={meta['arch']}  PIE={meta['pie']}  NX={meta['nx']}  "
      f"Canary={meta['canary']}  RELRO={meta['relro']}")

print("  [*] Enumerating sections...")
sections = get_sections(binary)
print(f"  [*] {len(sections)} sections found")

print("  [*] Loading symbol tables...")
static_syms, dyn_syms = get_symbols(binary)
print(f"  [*] Static: {len(static_syms)} functions  |  Dynamic: {len(dyn_syms)} imports")

print("  [*] Disassembling binary (Intel syntax)...")
asm_text = disassemble(binary)
func_map = parse_asm(asm_text)
print(f"  [*] {len(func_map)} functions parsed from disassembly")

print("  [*] Analyzing functions...")
func_analyses = {}
for fname, instructions in func_map.items():
    if instructions:
        func_analyses[fname] = analyze_function(fname, instructions)

dangerous_found = sum(
    len(a["dangerous_calls"]) for a in func_analyses.values())
print(f"  [*] Dangerous call sites: {dangerous_found}")

print("  [*] Scanning for win functions...")
win_fns = find_win_functions(func_analyses, {})
for wf in win_fns:
    print(f"  [+] Win function: {wf['function']}() → {wf['spawner']}()")

print("  [*] Extracting strings...")
str_table = get_rodata_strings(binary)

print("  [*] Scanning suspicious patterns...")
patterns = scan_patterns(binary, func_analyses, meta, sections, dyn_syms)
print(f"  [*] {len(patterns)} patterns flagged")

# Auto-detect input mode
stdin_funcs = {"gets","scanf","fscanf","fgets"}
file_funcs  = {"fopen","fread","open","read"}
arg_funcs   = {"strcpy","strcat","strlen","strcmp"}

has_stdin = any(
    any(dc["func_name"] in stdin_funcs for dc in a["dangerous_calls"])
    for a in func_analyses.values()
)
has_file  = any(name in dyn_syms for name in file_funcs)
input_mode_hint = "stdin" if has_stdin else ("file" if has_file else "arg")
print(f"  [*] Input mode auto-detected: {input_mode_hint}")

# ══════════════════════════════════════════════════════════════════════════
#  WRITE intermediate JSON
# ══════════════════════════════════════════════════════════════════════════
static_data = {
    "binary":           binary,
    "generated_at":     datetime.now(timezone.utc).isoformat(),
    "metadata":         meta,
    "sections":         sections,
    "functions": {
        fname: {
            "addr": f"{static_syms.get(fname,{}).get('addr',0):#010x}",
            "size": static_syms.get(fname,{}).get("size",0),
            "frame_size": a["frame_size"],
            "regs_used":  a["regs_used"],
            "calls":      [c["name"] for c in a["calls"]],
            "dangerous":  len(a["dangerous_calls"]) > 0,
        }
        for fname, a in func_analyses.items()
        if not fname.startswith("_") or fname in ("_start",)
    },
    "win_functions":    win_fns,
    "patterns":         patterns,
    "strings":          str_table[:30],
    "input_mode_hint":  input_mode_hint,
    "dynamic_imports":  list(dyn_syms.keys()),
}
with open(static_json,"w") as f:
    json.dump(static_data, f, indent=2)

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 0: Disassembly Report
# ══════════════════════════════════════════════════════════════════════════
SEP1 = "─" * 72

def md_code(text, lang=""):
    return f"```{lang}\n{text}\n```"

lines = []
lines += [
    "# [PHASE 0 OUTPUT]",
    "# Binary Security Analysis — Disassembly & Initial Pattern Detection",
    "",
    md_code(
        f"Binary    : {binary}\n"
        f"BuildID   : {meta.get('build_id','n/a')}\n"
        f"Format    : {meta['file_info'][:120]}\n"
        f"Type      : ELF\n"
        f"Architecture : {meta['arch']} ({meta['bits']}-bit)\n"
        f"Stripped  : {meta['stripped']}\n"
        f"Compiler  : detected via .comment / annobin",
    ),
    "",
    "---",
    "",
    "## SECURITY PROPERTIES",
    "",
    md_code(
        f"Mitigation       State     Detail\n"
        f"{SEP1}\n"
        f"PIE              {'OFF' if not meta['pie'] else 'ON':8s}  "
        f"{'Fixed base 0x400000' if not meta['pie'] else 'ASLR on binary'}\n"
        f"Stack Canary     {'ABSENT' if not meta['canary'] else 'PRESENT':8s}  "
        f"{'Overflow is silent — no abort()' if not meta['canary'] else '__stack_chk_fail present'}\n"
        f"NX / DEP         {'DISABLED' if not meta['nx'] else 'ENABLED':8s}  "
        f"{'Stack+heap executable; shellcode viable' if not meta['nx'] else 'Non-executable stack'}\n"
        f"RELRO            {meta['relro'].upper():8s}  "
        f"{'GOT writable at runtime' if meta['relro']=='partial' else '.got.plt frozen' if meta['relro']=='full' else 'No GOT protection'}\n"
        f"ASLR             Level {meta['aslr_level']}   "
        f"{'Affects libs/stack only (no PIE)' if not meta['pie'] else 'Full address randomization'}"
    ),
    "",
    "---",
    "",
    "## SECTIONS",
    "",
    "```",
    f"{'Section':<20} {'Address':<14} {'Size (bytes)':>12}  Flags",
    SEP1,
]
for sec in sections:
    if sec["size"] > 0:
        lines.append(
            f"{sec['name']:<20} {sec['addr']:<14} {sec['size']:>12}  {sec['flags']}"
        )
lines += ["```", "", "---", ""]

lines += [
    f"## FUNCTIONS IDENTIFIED: {len([f for f in func_analyses])}",
    "",
]
for fname, a in func_analyses.items():
    sym = static_syms.get(fname, {})
    addr_s = f"0x{sym.get('addr',0):08x}" if sym.get("addr") else "0x????????"
    size_s = str(sym.get("size",0))
    danger_mark = "  ⚑ DANGEROUS" if a["dangerous_calls"] else ""
    win_mark    = "  ★ WIN FN"    if any(wf["function"]==fname for wf in win_fns) else ""
    lines += [
        f"### `{fname}` @ {addr_s}  (size: {size_s} bytes){danger_mark}{win_mark}",
        "",
        f"- **Stack frame size**: {a['frame_size']} bytes",
        f"- **Registers used**: `{'`, `'.join(a['regs_used']) or 'n/a'}`",
        f"- **Calls**: {', '.join('`'+c['name']+'`' for c in a['calls']) or 'none'}",
    ]
    if a["dangerous_calls"]:
        lines.append("")
        for dc in a["dangerous_calls"]:
            lines.append(f"  - ⚑ **`{dc['func_name']}()`** @ `{dc['call_addr']:#010x}` — {dc['reason']}")
            if dc.get("rip_offset"):
                lines.append(f"    - Analytical RIP offset: **{dc['rip_offset']} bytes** (buf={dc.get('buf_size','?')}B + 8B saved-RBP)")
    lines.append("")

lines += ["---", "", "## SUSPICIOUS PATTERNS DETECTED", ""]
for idx, p in enumerate(patterns, 1):
    addr_s = f"0x{p['call_addr']:08x}" if p["call_addr"] else "[binary-wide]"
    lines.append(
        f"{idx}. `{addr_s}` — **{p['func_name']}** in `{p['in_function']}`  "
        f"[{p['severity']}] {p['type']}"
    )
    lines.append(f"   > {p['reason']}")
    lines.append("")

# Dynamic imports section
lines += ["---","","## DYNAMIC IMPORT RISK MATRIX","","```",
          f"{'Import':<14} {'Risk':<10} Notes",SEP1]
for imp in list(dyn_syms.keys()):
    if imp in DANGEROUS_FUNCS:
        di = DANGEROUS_FUNCS[imp]
        lines.append(f"{imp:<14} {di['severity']:<10} {di['reason'][:55]}")
lines += ["```",""]

with open(disasm_md,"w") as f:
    f.write("\n".join(lines))
print(f"  [+] Phase 0 disassembly report → {disasm_md}")

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 0.5: Vulnerability Classification Report
# ══════════════════════════════════════════════════════════════════════════
def sev_sort(p):
    return -SEV_ORDER.get(p["severity"],0)

sorted_pats = sorted(patterns, key=sev_sort)

vlines = [
    "# [PHASE 0.5 VULNERABILITY CLASSIFICATION]",
    f"# {os.path.basename(binary)} — Structured Vulnerability Catalog",
    "",
]

for vidx, p in enumerate(sorted_pats, 1):
    addr_s = f"0x{p['call_addr']:08x}" if p["call_addr"] else "[binary-wide]"
    fn_sym = static_syms.get(p["in_function"],{})
    fn_addr = f"0x{fn_sym.get('addr',0):08x}" if fn_sym.get("addr") else "?"

    # Build code context from disassembly
    ctx_lines = []
    fn_analysis = func_analyses.get(p["in_function"],{})
    ins_list = fn_analysis.get("instructions_text",[])
    if p["call_addr"] and ins_list:
        target_idx = next(
            (i for i, l in enumerate(ins_list)
             if f"{p['call_addr']:#010x}" in l), None
        )
        if target_idx is not None:
            lo = max(0, target_idx - 3)
            hi = min(len(ins_list), target_idx + 4)
            for i, l in enumerate(ins_list[lo:hi], lo):
                marker = "→ " if (lo+i) == target_idx else "  "
                ctx_lines.append(f"  {marker}{l.strip()}")

    # Determine attack vector narrative
    av_text = {
        "STACK_BUFFER_OVERFLOW": (
            f"Send >{p.get('buf_size') or '?'} bytes via {p['input_hint']}. "
            f"Overflow overwrites saved RBP (+{p.get('buf_size') or '?'}B) then saved RIP "
            f"(+{p.get('rip_offset') or '?'}B). Redirect RIP to win function or shellcode."
        ),
        "COMMAND_INJECTION": (
            "Pass shell metacharacters in the argument that reaches system()/popen(). "
            "If argument is user-controlled: `; /bin/sh` causes shell execution."
        ),
        "FORMAT_STRING": (
            "Pass `%p.%p.%p` to leak stack values (info disclosure). "
            "Pass `%n` to write controlled values to arbitrary addresses."
        ),
        "EXECUTABLE_STACK": (
            "Deposit shellcode in the stack buffer via the overflow primitive, "
            "then redirect RIP to &buf. Stack is RWX; shellcode runs directly."
        ),
        "WRITABLE_GOT": (
            "Using an arbitrary write primitive (e.g., ROP chain), overwrite a "
            "GOT entry to redirect the next call to that function to attacker code."
        ),
        "MISSING_STACK_CANARY": (
            "No stack canary means the overflow in P001 is undetected at runtime. "
            "Enables silent return address overwrite."
        ),
        "INFORMATION_DISCLOSURE": (
            "Read the printed address from stdout before sending the exploit payload. "
            "If PIE is enabled, this leaks the binary base and defeats ASLR."
        ),
    }.get(p["type"], "See root cause above.")

    remediation = {
        "STACK_BUFFER_OVERFLOW":
            "Replace gets/strcpy/sprintf with fgets/strlcpy/snprintf. "
            "Compile with -fstack-protector-all -D_FORTIFY_SOURCE=2.",
        "COMMAND_INJECTION":
            "Use execve() with an explicit argv[] array instead of system(). "
            "Validate and whitelist all user inputs before shell operations.",
        "FORMAT_STRING":
            "Always use a constant format string: printf(\"%s\", user_input). "
            "Never pass user data as the format argument.",
        "EXECUTABLE_STACK":
            "Compile with -z noexecstack. Verify with: readelf -l binary | grep GNU_STACK.",
        "WRITABLE_GOT":
            "Link with -Wl,-z,relro,-z,now (Full RELRO) to freeze .got.plt at startup.",
        "MISSING_STACK_CANARY":
            "Compile with -fstack-protector-all to insert stack canaries in all functions.",
        "INFORMATION_DISCLOSURE":
            "Remove debug printf statements that print function or memory addresses.",
    }.get(p["type"], "Apply principle of least privilege; validate all inputs.")

    # Win functions relevant to this vuln
    win_notes = []
    if p["type"] == "STACK_BUFFER_OVERFLOW" and win_fns:
        for wf in win_fns:
            fn_s = static_syms.get(wf["function"],{})
            wa   = f"0x{fn_s.get('addr',0):08x}" if fn_s.get("addr") else "?"
            win_notes.append(f"`{wf['function']}()` @ `{wa}` → `{wf['spawner']}()`")

    vlines += [
        f"## VULNERABILITY #{vidx}",
        SEP1,
        "",
        f"```",
        f"Location    : {addr_s}  (in {p['in_function']}())",
        f"Type        : {p['type']}",
        f"Severity    : {p['severity']}",
        f"Confidence  : {p['confidence']}",
        f"CWE         : {p['cwe']}",
        f"```",
        "",
        "### Code Context",
        "",
        "```asm",
        "\n".join(ctx_lines) if ctx_lines else f"  ; {p['func_name']} — {addr_s}",
        "```",
        "",
        "### Root Cause",
        "",
        f"> {p['reason']}",
        "",
        "### Attack Vector",
        "",
        f"> {av_text}",
    ]

    if p.get("rip_offset"):
        vlines += [
            "",
            "### Exploitation Data",
            "",
            "```",
            f"Buffer size      : {p.get('buf_size','?')} bytes",
            f"Offset to RIP    : {p['rip_offset']} bytes  (0x{p['rip_offset']:02x})",
            f"Input channel    : {p['input_hint']}",
            f"Method           : {'p64(win_fn)' if win_fns else 'p64(shellcode_addr)'}",
            "```",
        ]

    vlines += [
        "",
        "### Impact",
        "",
        {
            "STACK_BUFFER_OVERFLOW": "**Code execution** — arbitrary RIP control; shell via ret2win or shellcode.",
            "COMMAND_INJECTION":     "**Code execution** — arbitrary OS commands at process privilege level.",
            "FORMAT_STRING":         "**Information disclosure + arbitrary write** — stack leak and %n write primitive.",
            "EXECUTABLE_STACK":      "**Code execution** — shellcode injection path; amplifies stack overflow.",
            "WRITABLE_GOT":          "**Code execution** — function pointer hijack; persistent across calls.",
            "MISSING_STACK_CANARY":  "**Enables overflow** — silent stack corruption; facilitates Vuln #1.",
            "INFORMATION_DISCLOSURE":"**Address leak** — enables ASLR bypass if PIE later enabled.",
        }.get(p["type"], "See attack vector."),
        "",
        "### Affected Function(s)",
        "",
        f"- `{p['in_function']}()` @ `{fn_addr}`",
    ]

    if win_notes:
        vlines += ["", "### Ret2Win Targets (reachable via RIP overwrite)", ""]
        for wn in win_notes:
            vlines.append(f"- {wn}")

    vlines += [
        "",
        "### Dependencies",
        "",
        f"- {p.get('input_hint','any').upper()} input delivery required",
        f"- PIE=OFF: addresses are static  ({'✓ satisfied' if not meta['pie'] else '✗ requires leak'})",
        f"- Stack canary: {'✓ absent — overflow silent' if not meta['canary'] else '✗ present — needs bypass'}",
        "",
        "### Remediation",
        "",
        f"> {remediation}",
        "",
        "---",
        "",
    ]

# SUMMARY
counts = defaultdict(int)
for p in patterns:
    counts[p["severity"]] += 1
vlines += [
    "## SUMMARY",
    SEP1,
    "",
    "```",
    f"Total Vulnerabilities Found : {len(patterns)}",
    f"Critical : {counts['CRITICAL']}  |  "
    f"High : {counts['HIGH']}  |  "
    f"Medium : {counts['MEDIUM']}  |  "
    f"Low : {counts['LOW']}",
    "```",
    "",
    "### Vulnerability Matrix",
    "",
    "```",
    f"{'#':<4} {'ID':<8} {'Address':<14} {'Type':<28} {'Severity':<10} Confidence",
    SEP1,
]
for vidx, p in enumerate(sorted_pats, 1):
    addr_s = f"0x{p['call_addr']:08x}" if p["call_addr"] else "[binary-wide]"
    vlines.append(
        f"{vidx:<4} {p['id']:<8} {addr_s:<14} {p['type']:<28} {p['severity']:<10} {p['confidence']}"
    )
vlines += ["```","","### False-Positive Disclaimers",""]
vlines.append(
    "- `printf(\"format\", buf)` — **NOT** a format string vuln: format arg is "
    "a const string literal; user data only reaches `%s` argument slot (safe)."
)
vlines.append(
    "- `system()` import presence — **NOT** command injection by itself: "
    "classified as WIN FUNCTION if called with const arg from unreachable fn."
)

with open(class_md,"w") as f:
    f.write("\n".join(vlines))
print(f"  [+] Phase 0.5 classification → {class_md}")

# ══════════════════════════════════════════════════════════════════════════
#  HAND-OFF SUMMARY
# ══════════════════════════════════════════════════════════════════════════
top3 = sorted_pats[:3]
hlines = [
    "# HAND-OFF SUMMARY",
    f"# {os.path.basename(binary)} — Executive Brief for Phases 1–4",
    SEP1, "",
    "## Binary Identity", "",
    "```",
    f"File         : {binary}",
    f"BuildID      : {meta.get('build_id','n/a')}",
    f"Architecture : {meta['arch']} ({meta['bits']}-bit)",
    f"PIE          : {'OFF — fixed base 0x400000' if not meta['pie'] else 'ON — ASLR on binary'}",
    f"Symbols      : {'present (not stripped)' if not meta['stripped'] else 'stripped'}",
    "```", "",
    "## Security State", "",
    "```",
    f"{'Mitigation':<18} {'State':<10} Impact",
    SEP1,
    f"{'PIE':<18} {'OFF' if not meta['pie'] else 'ON':<10} "
    f"{'Addresses fixed' if not meta['pie'] else 'ASLR — binary base randomized'}",
    f"{'Stack Canary':<18} {'ABSENT' if not meta['canary'] else 'PRESENT':<10} "
    f"{'Overflow undetected' if not meta['canary'] else 'Canary check on ret'}",
    f"{'NX / DEP':<18} {'DISABLED' if not meta['nx'] else 'ENABLED':<10} "
    f"{'Shellcode on stack executable' if not meta['nx'] else 'Non-executable stack'}",
    f"{'RELRO':<18} {meta['relro'].upper():<10} "
    f"{'GOT writable runtime' if meta['relro'] in ('partial','none') else 'GOT frozen'}",
    "```", "",
    "## TOP 3 CRITICAL VULNERABILITIES", "",
]
for rank, p in enumerate(top3, 1):
    addr_s = f"0x{p['call_addr']:08x}" if p["call_addr"] else "[binary-wide]"
    hlines += [
        f"### {rank}. [{p['severity']}] {p['type']}  —  `{p['func_name']}` @ `{addr_s}`", "",
        "```",
        f"Function : {p['in_function']}()",
        f"CWE      : {p['cwe']}",
    ]
    if p.get("buf_size"):    hlines.append(f"Buf size : {p['buf_size']} bytes")
    if p.get("rip_offset"):  hlines.append(f"RIP offset: {p['rip_offset']} bytes  (0x{p['rip_offset']:02x})")
    if p.get("input_hint"):  hlines.append(f"Channel  : {p['input_hint']}")
    hlines += [
        "```", "",
        f"> {p['reason']}", "",
    ]
    if p.get("rip_offset") and win_fns:
        fn_s = static_syms.get(win_fns[0]["function"],{})
        wa = f"0x{fn_s.get('addr',0):08x}"
        hlines += [
            "**Minimal payload:**",
            "```python",
            f"payload = b'A' * {p['rip_offset']} + p64({wa})  "
            f"# → {win_fns[0]['function']}() → {win_fns[0]['spawner']}()",
            "```", "",
        ]

# Key addresses table
hlines += ["## KEY ADDRESSES (all static — PIE=OFF)", "", "```",
           f"{'Symbol':<30} {'Address':<14} Notes",SEP1]
for sname, sdata in static_syms.items():
    if sdata.get("addr") and sdata["addr"] > 0:
        mark = "★" if any(wf["function"]==sname for wf in win_fns) else \
               "⚑" if any(p["in_function"]==sname and p.get("rip_offset") for p in patterns) else " "
        hlines.append(f"{mark} {sname:<28} 0x{sdata['addr']:08x}")
for imp in list(dyn_syms.keys())[:8]:
    if imp in DANGEROUS_FUNCS or imp in SHELL_SPAWNERS:
        hlines.append(f"  {imp+'@plt':<28} (PLT stub — see disassembly)")
hlines += ["```",""]

# Exploitation order
exp_order = []
if any(p["type"]=="STACK_BUFFER_OVERFLOW" and p.get("rip_offset") for p in patterns):
    exp_order.append(("ret2win", "TRIVIAL", "None", "RIP offset + win fn addr"))
if not meta["nx"]:
    exp_order.append(("Shellcode on stack","LOW","Stack address (ASLR or leak)","Shellcode + &buf"))
if meta["relro"] in ("partial","none"):
    exp_order.append(("GOT overwrite","MEDIUM","Arbitrary write + ROP","Write to .got.plt"))

hlines += ["## RECOMMENDED EXPLOITATION ORDER","",
           "```",
           f"{'Path':<22} {'Difficulty':<12} {'Prerequisites':<30} Payload",SEP1]
for path, diff, prereq, payload in exp_order:
    hlines.append(f"{path:<22} {diff:<12} {prereq:<30} {payload}")
hlines += ["```",""]

hlines += [
    "## PHASE 0 ROOT CAUSE FIX", "",
    "```bash",
    "# If Phase 0 returned zero findings:",
    f"# Auto-detected input mode: {input_mode_hint}",
    f"./phase0_vuln_detection.sh -b {os.path.basename(binary)} -i {input_mode_hint}",
    "# Static analysis always runs regardless of fuzzer results.",
    "```", "",
    "## QUICK VALIDATION", "",
    "```bash",
]
if any(p["type"]=="STACK_BUFFER_OVERFLOW" and p.get("rip_offset") for p in patterns):
    bof = next(p for p in patterns
               if p["type"]=="STACK_BUFFER_OVERFLOW" and p.get("rip_offset"))
    fn_s = static_syms.get(win_fns[0]["function"],{}) if win_fns else {}
    wa   = f"0x{fn_s.get('addr',0):08x}" if fn_s.get("addr") else "0x????????"
    hlines += [
        f"python3 -c \"import struct,sys; sys.stdout.buffer.write(",
        f"  b'A'*{bof['rip_offset']}+struct.pack('<Q',{wa})+b'\\n')\" \\",
        f"  | ./{os.path.basename(binary)}",
        "# Expected: win function output + shell",
    ]
hlines += ["```",""]

with open(handoff_md,"w") as f:
    f.write("\n".join(hlines))
print(f"  [+] Hand-off summary      → {handoff_md}")
print(f"  [+] Static analysis JSON  → {static_json}")
PYEOF

# ── Read auto-detected input mode from static analysis ───────────────────
DETECTED_MODE=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATIC_JSON'))
    print(d.get('input_mode_hint','file'))
except Exception:
    print('file')
" 2>/dev/null || echo "file")

# Override INPUT_MODE if it was 'auto'
if [ "$INPUT_MODE" = "auto" ]; then
    INPUT_MODE="$DETECTED_MODE"
    warn "Input mode auto-detected: $INPUT_MODE"
fi

ok "Stage A complete — Phase 0 / 0.5 reports written"
ok "Input mode (final): $INPUT_MODE"

# ══════════════════════════════════════════════════════════════════════════
#  STAGE B — STEP 3: Targeted Seed Corpus
# ══════════════════════════════════════════════════════════════════════════
step "Stage B · Step 3: Seed Corpus (targeted from Stage A)"

if [ -n "$SEED_DIR" ] && [ -d "$SEED_DIR" ]; then
    AUTO_SEED="$SEED_DIR"
    ok "Using provided seed corpus: $SEED_DIR"
else
    AUTO_SEED="$OUTPUT_DIR/phase0_seeds"
    mkdir -p "$AUTO_SEED"

    # Generic seeds
    printf 'A'                          > "$AUTO_SEED/seed_01_byte"
    python3 -c "sys.stdout.buffer.write(b'A'*64+b'\n')" 2>/dev/null \
        || python3 -c "import sys; sys.stdout.buffer.write(b'A'*64+b'\n')" \
        > "$AUTO_SEED/seed_02_64" 2>/dev/null || printf '%0.sA' {1..64} > "$AUTO_SEED/seed_02_64"
    python3 -c "import sys; sys.stdout.buffer.write(b'A'*256+b'\n')" > "$AUTO_SEED/seed_03_256"
    python3 -c "import sys; sys.stdout.buffer.write(b'%s'*20+b'\n')" > "$AUTO_SEED/seed_04_fmt"
    python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*32+b'\n')" > "$AUTO_SEED/seed_05_null"
    python3 -c "import sys; sys.stdout.buffer.write(b'/../'*20+b'\n')" > "$AUTO_SEED/seed_06_path"
    printf '%s\n' "-1" > "$AUTO_SEED/seed_07_neg"
    python3 -c "import sys; sys.stdout.buffer.write(b'A'*512+b'\n')" > "$AUTO_SEED/seed_08_512"

    # Targeted overflow seeds derived from Stage A static analysis
    python3 - "$STATIC_JSON" "$AUTO_SEED" << 'PYEOF2'
import json, sys, os, struct

static_json = sys.argv[1]
seed_dir    = sys.argv[2]

try:
    data = json.load(open(static_json))
except Exception:
    print("  [!] Cannot load static JSON — using generic seeds only")
    sys.exit(0)

patterns = data.get("patterns", [])
generated = 0

for p in patterns:
    offset = p.get("rip_offset")
    buf_sz = p.get("buf_size")
    fn     = p.get("func_name","?")

    if not offset:
        continue

    # Seed 1: exact overflow length (should trigger crash)
    for pad in (offset, offset + 8, offset + 16, offset + 32, offset + 64):
        name = f"seed_target_{fn}_{pad}b"
        with open(os.path.join(seed_dir, name), "wb") as f:
            f.write(b"A" * pad + b"\n")

    # Seed 2: cyclic pattern for offset verification
    try:
        from pwn import cyclic
        pat = cyclic(min(offset + 32, 600))
        with open(os.path.join(seed_dir, f"seed_cyclic_{fn}"), "wb") as f:
            f.write(pat + b"\n")
        generated += 1
    except ImportError:
        pass

    print(f"  [+] Targeted seeds for {fn}: offsets {offset}…{offset+64}")

print(f"  [+] {generated} cyclic pattern seeds generated")
PYEOF2

    ok "Seed corpus: $AUTO_SEED  ($(ls "$AUTO_SEED" | wc -l | tr -d ' ') seeds)"
fi

# ══════════════════════════════════════════════════════════════════════════
#  STAGE B — STEP 4: AFL++ Fuzzing
# ══════════════════════════════════════════════════════════════════════════
step "Stage B · Step 4: Fuzzing"

if [ "${SKIP_DYNAMIC:-0}" = "1" ]; then
    warn "Stage B skipped (-S 1); using static-only findings"
    CRASHES_FOUND=0

elif [ -n "$CRASH_CORPUS" ]; then
    warn "Skip-fuzz mode — importing crashes from $CRASH_CORPUS"
    find "$CRASH_CORPUS" -type f | while IFS= read -r f; do
        cp "$f" "$CRASH_DIR/$(basename "$f")"
    done
    CRASHES_FOUND=$(ls "$CRASH_DIR" | wc -l | tr -d ' ')
    ok "Imported $CRASHES_FOUND crash inputs"

elif [ "$HAVE_AFL" = "false" ]; then
    warn "afl-fuzz not found — Stage B fuzzing skipped; using static findings"
    CRASHES_FOUND=0

else
    log "Running AFL++ for ${FUZZ_TIMEOUT}s  (jobs: $AFL_JOBS  mode: $INPUT_MODE)"

    case "$INPUT_MODE" in
        file)   AFL_TARGET="$BINARY_ABS @@" ;;
        stdin)  AFL_TARGET="$BINARY_ABS" ;;
        arg)
            SHIM="$OUTPUT_DIR/phase0_arg_shim.sh"
            printf '#!/bin/sh\nexec "$1" "$(cat "$2")"\n' > "$SHIM"
            chmod +x "$SHIM"
            AFL_TARGET="$SHIM $BINARY_ABS @@"
            ;;
    esac

    ( ulimit -c 0
      AFL_SKIP_CPUFREQ=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      timeout "$FUZZ_TIMEOUT" \
          afl-fuzz \
              -i "$AUTO_SEED" \
              -o "$AFL_OUT" \
              -m "$MEM_LIMIT" \
              $( [ "$AFL_JOBS" -gt 1 ] \
                 && printf -- "-M main -S s%s " $(seq 1 $((AFL_JOBS-1))) ) \
              -- $AFL_TARGET
    ) 2>"$OUTPUT_DIR/afl_stderr.log" || true

    find "$AFL_OUT" -path "*/crashes/id:*" -type f 2>/dev/null \
        | sort -u | while IFS= read -r cf; do
            cp "$cf" "$CRASH_DIR/$(basename "$cf")"
        done
    CRASHES_FOUND=$(ls "$CRASH_DIR" 2>/dev/null | wc -l | tr -d ' ')
    ok "AFL++ finished — unique crashes: $CRASHES_FOUND"
fi

# ══════════════════════════════════════════════════════════════════════════
#  STAGE B — STEPS 5-7: Crash Triage + GDB + Cyclic Probing
# ══════════════════════════════════════════════════════════════════════════
step "Stage B · Steps 5-7: Crash Triage + Primitive Extraction"

python3 - \
    "$BINARY_ABS" \
    "$CRASH_DIR" \
    "$OUTPUT_DIR" \
    "$INPUT_MODE" \
    "${ASAN_BINARY:-NONE}" \
    "$STATIC_JSON" \
<< 'PYEOF3'
import sys, os, re, json, subprocess, tempfile, gc, hashlib, signal
from datetime import datetime, timezone
from collections import defaultdict

binary      = sys.argv[1]
crash_dir   = sys.argv[2]
output_dir  = sys.argv[3]
input_mode  = sys.argv[4]
asan_binary = sys.argv[5] if sys.argv[5] != "NONE" else None
static_json = sys.argv[6]

# Load static analysis for merge
static_data = {}
try:
    with open(static_json) as f:
        static_data = json.load(f)
except Exception:
    pass

TRIAGE_TIMEOUT = 20
PATTERN_LEN    = 600
MAX_CRASHES    = 50
GPR = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
       "r8","r9","r10","r11","r12","r13","r14","r15","rip"]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()[:16]

def run_binary(binary, input_path, input_mode, timeout=5, extra_env=None):
    env = os.environ.copy()
    if extra_env: env.update(extra_env)
    try:
        if input_mode == "stdin":
            with open(input_path,"rb") as inp:
                r = subprocess.run([binary], stdin=inp, capture_output=True,
                                   timeout=timeout, env=env)
        elif input_mode == "arg":
            data = open(input_path,"rb").read().decode(errors="replace").strip()
            r = subprocess.run([binary, data], capture_output=True,
                               timeout=timeout, env=env)
        else:
            r = subprocess.run([binary, input_path], capture_output=True,
                               timeout=timeout, env=env)
        return r.returncode, r.stderr.decode(errors="replace"), \
               r.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -999, "TIMEOUT", ""
    except Exception as exc:
        return -998, str(exc), ""

GDB_SCRIPT = r"""
import gdb, json, re
output_file = "{output_file}"
input_path  = "{input_path}"
input_mode  = "{input_mode}"
gdb.execute("set pagination off")
gdb.execute("set print pretty off")
gdb.execute("set disassembly-flavor intel")
gdb.execute("set confirm off")
try:
    gdb.execute("file {binary}")
    if input_mode == "stdin":
        gdb.execute("run < " + input_path)
    elif input_mode == "arg":
        data = open(input_path).read().strip().replace('"','\\"')
        gdb.execute('run "' + data + '"')
    else:
        gdb.execute("run " + input_path)
except gdb.error:
    pass
result = {{"crashed":False,"signal":"NONE","fault_address":"0x0",
           "registers":{{}},"stack_top":[],"backtrace":[],"maps":[]}}
try:
    stop = gdb.execute("info program", to_string=True)
    for sig in ["SIGSEGV","SIGABRT","SIGBUS","SIGFPE","SIGILL"]:
        if sig in stop:
            result["crashed"] = True
            result["signal"]  = sig
            break
    regs_raw = gdb.execute("info registers", to_string=True)
    for line in regs_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].lower().lstrip("$")
            val  = parts[1]
            if re.match(r"^0x[0-9a-f]+$", val):
                result["registers"][name] = val
    try:
        si = gdb.execute("print $_siginfo", to_string=True)
        fm = re.search(r"si_addr\s*=\s*(0x[0-9a-f]+)", si)
        if fm: result["fault_address"] = fm.group(1)
    except Exception:
        pass
    try:
        rsp = result["registers"].get("rsp","0x0")
        stk = gdb.execute("x/16gx " + rsp, to_string=True)
        for line in stk.splitlines():
            for m in re.finditer(r"0x[0-9a-f]+", line):
                result["stack_top"].append(m.group(0))
    except Exception:
        pass
    try:
        bt = gdb.execute("bt 10", to_string=True)
        result["backtrace"] = [l.strip() for l in bt.splitlines() if l.strip()][:10]
    except Exception:
        pass
    try:
        maps = gdb.execute("info proc mappings", to_string=True)
        for line in maps.splitlines():
            m = re.match(r"\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\S+\s+\S+\s+(.*)", line)
            if m:
                result["maps"].append({{"start":m.group(1),"end":m.group(2),"path":m.group(3).strip()}})
    except Exception:
        pass
except Exception as exc:
    result["gdb_error"] = str(exc)
with open(output_file,"w") as fh:
    json.dump(result, fh)
gdb.execute("quit")
"""

def run_gdb(binary, input_path, input_mode, output_file):
    if not _HAVE_GDB: return {"crashed":False,"gdb_error":"gdb not installed"}
    script = GDB_SCRIPT.format(
        binary=binary.replace('"','\\"'),
        input_path=input_path.replace('"','\\"'),
        input_mode=input_mode,
        output_file=output_file.replace('"','\\"'),
    )
    sp = output_file + ".gdbpy"
    with open(sp,"w") as f: f.write(script)
    try:
        subprocess.run(["gdb","-batch","-nx","-x",sp],
                       capture_output=True, timeout=TRIAGE_TIMEOUT)
    except Exception:
        pass
    finally:
        try: os.unlink(sp)
        except: pass
    if os.path.exists(output_file):
        try:
            with open(output_file) as f: return json.load(f)
        except: pass
    return {"crashed":False,"gdb_error":"no output"}

_HAVE_GDB = bool(subprocess.run(["which","gdb"],capture_output=True).returncode == 0)

HAVE_PWN = False
try:
    from pwn import cyclic, cyclic_find, context
    context.arch = "amd64"; context.log_level = "error"
    HAVE_PWN = True
except ImportError:
    pass

def probe_offset(binary, crash_path, input_mode):
    if not HAVE_PWN: return None, None
    pattern = cyclic(PATTERN_LEN)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pat") as tf:
        tf.write(pattern); pat_path = tf.name
    gdb_out = pat_path + ".json"
    result  = run_gdb(binary, pat_path, input_mode, gdb_out)
    try: os.unlink(pat_path)
    except: pass
    try: os.unlink(gdb_out)
    except: pass
    if not result.get("crashed"): return None, None
    for reg, via in [("rip","RIP"),("fault_address","FAULT_ADDR"),("rsp","RSP")]:
        val = result["registers"].get(reg) or result.get(reg,"0x0")
        try:
            b = int(val,16).to_bytes(8,"little")[:4]
            off = cyclic_find(b)
            if off >= 0: return off, via
        except: pass
    return None, None

def classify_primitive(result, offset_via):
    sig = result.get("signal","NONE")
    fa  = result.get("fault_address","0x0")
    rip = result.get("registers",{}).get("rip","0x0")
    def has_pat(h):
        try:
            if not HAVE_PWN: return False
            b = int(h,16).to_bytes(8,"little")[:4]
            return cyclic_find(b) >= 0
        except: return False
    if offset_via == "RIP" or has_pat(rip):
        return "RETURN_ADDRESS_OVERWRITE","HIGH","Attacker controls RIP"
    if offset_via == "FAULT_ADDR" or has_pat(fa):
        return "ARBITRARY_WRITE","HIGH","Fault at attacker-controlled address"
    if offset_via == "RSP":
        return "STACK_PIVOT","HIGH","RSP controlled — stack pivot"
    if sig == "SIGABRT":
        return "HEAP_CORRUPTION","MEDIUM","SIGABRT — heap metadata"
    if sig == "SIGILL":
        return "CONTROLLED_BRANCH","HIGH","SIGILL at controlled address"
    return "MEMORY_CORRUPTION","MEDIUM",f"Signal:{sig} fault:{fa}"

# Main triage loop
crash_files = sorted([
    os.path.join(crash_dir, f)
    for f in os.listdir(crash_dir)
    if os.path.isfile(os.path.join(crash_dir, f))
])[:MAX_CRASHES]

print(f"  [*] Triaging {len(crash_files)} crash input(s)...")
dynamic_vulns = []
seen_hashes   = set()

for idx, crash_path in enumerate(crash_files):
    cid   = "V%06d" % (idx + 1)
    chash = sha256_file(crash_path)
    print(f"  [*] {cid}  {os.path.basename(crash_path)}  ({idx+1}/{len(crash_files)})")
    if chash in seen_hashes:
        print("       duplicate — skipped")
        continue
    seen_hashes.add(chash)

    # ASAN first
    asan_type = None
    if asan_binary:
        _, asan_err, _ = run_binary(asan_binary, crash_path, input_mode, timeout=10,
                                    extra_env={"ASAN_OPTIONS":"halt_on_error=1:detect_leaks=0"})
        for key, val in [("stack-buffer-overflow","STACK_BUFFER_OVERFLOW"),
                         ("heap-buffer-overflow","HEAP_BUFFER_OVERFLOW"),
                         ("heap-use-after-free","HEAP_USE_AFTER_FREE"),
                         ("null-dereference","NULL_DEREF")]:
            if key in asan_err.lower(): asan_type = val; break

    gdb_out_path = os.path.join(output_dir, f"phase0_gdb_{cid}.json")
    result       = run_gdb(binary, crash_path, input_mode, gdb_out_path)
    try: os.unlink(gdb_out_path)
    except: pass

    if not result.get("crashed") and not asan_type:
        print("       no crash detected — skipping")
        continue

    offset_bytes, offset_via = None, None
    if result.get("crashed"):
        offset_bytes, offset_via = probe_offset(binary, crash_path, input_mode)
        if offset_bytes is not None:
            print(f"       offset to {offset_via}: {offset_bytes} bytes")

    primitive, exploitability, notes = classify_primitive(result, offset_via)
    print(f"       primitive: {primitive:<32}  exploitability: {exploitability}")

    ctrl_regs = []
    try:
        crash_bytes = open(crash_path,"rb").read()
        for reg in GPR:
            try:
                v = int(result.get("registers",{}).get(reg,"0x0"), 16)
                if v and v.to_bytes(8,"little")[:4] in crash_bytes:
                    ctrl_regs.append(reg)
            except: pass
    except: pass

    dynamic_vulns.append({
        "vuln_id": cid, "crash_input": crash_path,
        "input_hash": chash,
        "vuln_type": asan_type or ("MEMORY_CORRUPTION" if result.get("crashed") else "UNKNOWN"),
        "write_primitive": primitive,
        "controlled_offset": offset_bytes, "offset_via": offset_via,
        "exploitability": exploitability,
        "signal": result.get("signal","NONE"),
        "fault_address": result.get("fault_address","0x0"),
        "registers_at_crash": result.get("registers",{}),
        "controlled_registers": ctrl_regs,
        "stack_top": result.get("stack_top",[])[:8],
        "backtrace": result.get("backtrace",[])[:6],
        "memory_map": result.get("maps",[]),
        "notes": notes, "gdb_error": result.get("gdb_error",""),
    })
    gc.collect()

print(f"  [+] Dynamic triage: {len(dynamic_vulns)} exploitable crash(es)")

# Save dynamic results for merge step
dyn_path = os.path.join(output_dir, "phase0_dynamic.json")
with open(dyn_path,"w") as f:
    json.dump(dynamic_vulns, f, indent=2)
PYEOF3

# ══════════════════════════════════════════════════════════════════════════
#  STAGE B — STEP 8: Merge Static + Dynamic → Final JSON
# ══════════════════════════════════════════════════════════════════════════
step "Stage B · Step 8: Final Report Assembly"

python3 - \
    "$BINARY_ABS" \
    "$STATIC_JSON" \
    "$OUTPUT_DIR/phase0_dynamic.json" \
    "$REPORT_JSON" \
    "$INPUT_MODE" \
<< 'PYEOF4'
import sys, os, json, subprocess, re
from datetime import datetime, timezone

binary      = sys.argv[1]
static_json = sys.argv[2]
dynamic_json= sys.argv[3]
report_json = sys.argv[4]
input_mode  = sys.argv[5]

# Load static data
try:
    static = json.load(open(static_json))
except Exception:
    static = {"patterns":[],"metadata":{},"win_functions":[],"sections":[]}

# Load dynamic data
try:
    dynamic_vulns = json.load(open(dynamic_json))
except Exception:
    dynamic_vulns = []

meta = static.get("metadata",{})

# Runtime env (from static analysis + proc)
aslr_level = meta.get("aslr_level", 2)
try:
    with open("/proc/sys/kernel/randomize_va_space") as f:
        aslr_level = int(f.read().strip())
except: pass

runtime_env = {
    "aslr_level":   aslr_level,
    "pie_binary":   meta.get("pie", False),
    "stack_canary": meta.get("canary", False),
    "nx_enabled":   meta.get("nx", True),
    "full_relro":   meta.get("relro","none") == "full",
    "partial_relro":meta.get("relro","none") in ("partial","full"),
    "cet_ibt":      False,
    "cet_shstk":    False,
}

# Build static-derived vulnerability entries (for pipeline feed even without crashes)
static_vulns = []
patterns = static.get("patterns",[])
static_syms_raw = {}
try:
    out = subprocess.check_output(["readelf","-s","--wide",binary],
                                  text=True, stderr=subprocess.DEVNULL)
    for line in out.splitlines():
        m = re.match(r'\s+\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+\S+\s+(\S+)', line)
        if m:
            static_syms_raw[m.group(2)] = int(m.group(1),16)
except: pass

for p in patterns:
    if p.get("rip_offset") or p.get("call_addr"):
        ctrl_regs = ["rip","rsp","rbp"] if p["type"]=="STACK_BUFFER_OVERFLOW" else []
        static_vulns.append({
            "vuln_id":          f"S{p['id']}",
            "crash_input":      None,
            "input_hash":       "static-analysis",
            "vuln_type":        p["type"],
            "write_primitive":  p["type"],
            "controlled_offset":p.get("rip_offset"),
            "offset_via":       "RIP" if p.get("rip_offset") else None,
            "exploitability":   p["severity"],
            "confidence":       p.get("confidence",0.9),
            "signal":           "PREDICTED",
            "fault_address":    "0x4141414141414141",
            "registers_at_crash":{},
            "controlled_registers": ctrl_regs,
            "stack_top":        [],
            "backtrace":        [],
            "memory_map":       [],
            "notes":            p["reason"],
            "gdb_error":        "",
            "static_analysis":  True,
            "in_function":      p["in_function"],
            "call_addr":        f"0x{p['call_addr']:08x}" if p.get("call_addr") else None,
            "dangerous_func":   p["func_name"],
        })

# Win functions
win_fns = static.get("win_functions",[])
ret2win_targets = []
for wf in win_fns:
    addr = static_syms_raw.get(wf["function"], 0)
    ret2win_targets.append({
        "function": wf["function"],
        "address":  f"0x{addr:08x}" if addr else "0x????????",
        "spawner":  wf["spawner"],
    })

# All memory maps from dynamic vulns
all_maps = []
seen_paths = set()
for v in dynamic_vulns:
    for m in v.get("memory_map",[]):
        p = m.get("path","")
        if p and p not in seen_paths:
            seen_paths.add(p)
            all_maps.append(m)

# Merge: dynamic findings override static predictions if they cover same function
merged_vulns = []
dyn_fns = {v.get("in_function","?") for v in dynamic_vulns}
for sv in static_vulns:
    if sv["in_function"] not in dyn_fns:
        merged_vulns.append(sv)
merged_vulns.extend(dynamic_vulns)

all_ctrl_regs = sorted(set(
    r for v in merged_vulns for r in v.get("controlled_registers",[])
))

report = {
    "phase":                   0,
    "binary":                  binary,
    "generated_at":            datetime.now(timezone.utc).isoformat(),
    "input_mode":              input_mode,
    "crashes_triaged":         len(dynamic_vulns),
    "static_patterns_found":   len(patterns),
    "exploitable_found":       len(merged_vulns),
    "all_controlled_registers":all_ctrl_regs,
    "all_memory_maps":         all_maps,
    "runtime_env":             runtime_env,
    "ret2win_targets":         ret2win_targets,
    "vulnerabilities":         merged_vulns,
}
with open(report_json,"w") as f:
    json.dump(report, f, indent=2)
print(f"  [+] Final report → {report_json}")
print(f"  [+] Vulnerabilities: {len(merged_vulns)} "
      f"(static:{len(static_vulns)}  dynamic:{len(dynamic_vulns)})")
PYEOF4

# ── Terminal summary ──────────────────────────────────────────────────────
printf "\n${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  PHASE 0 COMPLETE${NC}\n"
printf "${BOLD}%s${NC}\n\n" "======================================================="

python3 -c "
import json, os

r  = json.load(open('$REPORT_JSON'))
sd = json.load(open('$STATIC_JSON')) if os.path.exists('$STATIC_JSON') else {}

print('  Binary    :', r['binary'])
print('  Input mode:', r['input_mode'])
print('  Static patterns  :', r.get('static_patterns_found', 0))
print('  Crashes triaged  :', r['crashes_triaged'])
print('  Exploitable found:', r['exploitable_found'])
print()

pats = sd.get('patterns',[])
by_sev = {}
for p in pats:
    by_sev.setdefault(p['severity'],[]).append(p)
for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
    for p in by_sev.get(sev,[]):
        addr = '0x%08x' % p['call_addr'] if p.get('call_addr') else '[binary-wide]'
        off  = '  offset=%dB' % p['rip_offset'] if p.get('rip_offset') else ''
        print('  [%s] %s @ %s in %s()%s' % (sev, p['type'], addr, p['in_function'], off))
print()

wins = r.get('ret2win_targets',[])
if wins:
    print('  Win functions:')
    for wf in wins:
        print('    %s @ %s → %s()' % (wf['function'], wf['address'], wf['spawner']))
    print()

crs = r.get('all_controlled_registers',[])
if crs:
    print('  Controlled registers:', crs)
" 2>/dev/null || true

printf "\n"
ok "JSON pipeline feed  → $REPORT_JSON"
ok "Phase 0  report     → $DISASM_MD"
ok "Phase 0.5 report    → $CLASS_MD"
ok "Hand-off summary    → $HANDOFF_MD"
ok "Crash inputs        → $CRASH_DIR"
printf "\n"
printf "${YELLOW}Next step:${NC}  ./phase1_opcode_collection.sh -b %s --phase0 %s\n" \
    "$BINARY_ABS" "$REPORT_JSON"
