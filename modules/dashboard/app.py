#!/usr/bin/env python3
"""
CRA Framework — Full Pipeline Dashboard
────────────────────────────────────────
Usage:
  pip install flask
  python app.py                          # uses ./cra_output/
  python app.py /path/to/cra_output      # explicit dir
  python app.py /path/to/cra_output --port 8080
"""
import json, os, sys, time
from flask import Flask, jsonify, render_template, redirect, url_for, request

app   = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# ── Global dir (mutable so /api/setdir can update it) ─────────────────────
_state = {"cra_dir": "../files/cra_output"}


def D():  return _state["cra_dir"]
def p(f): return os.path.join(D(), f)


# ── Loaders ───────────────────────────────────────────────────────────────
def load_json(relpath):
    fp = p(relpath)
    if not os.path.exists(fp):
        return None
    try:
        with open(fp) as f:
            return json.load(f)
    except Exception as e:
        return {"_error": str(e), "_path": fp}


def load_text(relpath, max_bytes=256_000):
    fp = p(relpath)
    if not os.path.exists(fp):
        return None
    try:
        with open(fp, "rb") as f:
            raw = f.read(max_bytes)
        text = raw.decode("utf-8", errors="replace")
        if len(raw) == max_bytes:
            text += "\n… (truncated)"
        return text
    except Exception:
        return None


def load_json_header(relpath):
    """Read metadata keys from a large Phase-1/2 catalog without loading gadgets."""
    fp = p(relpath)
    if not os.path.exists(fp):
        return None
    try:
        lines = []
        with open(fp) as f:
            for line in f:
                if '"gadgets"' in line:
                    break
                lines.append(line)
        text = "".join(lines).rstrip().rstrip(",") + "\n}"
        return json.loads(text)
    except Exception as e:
        return {"_error": str(e)}


def parse_afl_plot():
    fp = p("afl_output/default/plot_data")
    if not os.path.exists(fp):
        return None
    headers, rows = None, []
    try:
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    headers = [h.strip().lstrip("# ") for h in line[1:].split(",")]
                    continue
                if headers is None:
                    continue
                parts = [v.strip() for v in line.split(",")]
                if len(parts) != len(headers):
                    continue
                row = {}
                for k, v in zip(headers, parts):
                    try:
                        row[k] = float(v.rstrip("%"))
                    except ValueError:
                        row[k] = v
                rows.append(row)
    except Exception:
        return None
    return {"headers": headers or [], "rows": rows}


def afl_dir_stats():
    stats = {"queue": 0, "crashes": 0, "hangs": 0, "cmdline": ""}
    for key, subdir in [("queue","queue"), ("crashes","crashes"), ("hangs","hangs")]:
        d = p(f"afl_output/default/{subdir}")
        if os.path.isdir(d):
            stats[key] = len([f for f in os.listdir(d) if f.startswith("id:")])
    cl = p("afl_output/default/cmdline")
    if os.path.exists(cl):
        with open(cl) as f:
            stats["cmdline"] = f.read().strip().replace("\x00", " ")
    return stats


def seed_list():
    sd = p("phase0_seeds")
    if not os.path.isdir(sd):
        return []
    out = []
    for fname in sorted(os.listdir(sd)):
        fp2 = os.path.join(sd, fname)
        if os.path.isfile(fp2):
            out.append({"name": fname, "size": os.path.getsize(fp2)})
    return out


def pipeline_status():
    files = {
        "phase0_vuln_report.json":           "Phase 0 — Detection",
        "phase0_static.json":                "Phase 0 — Static analysis",
        "phase1_gadget_catalog.json":        "Phase 1 — Gadget catalog",
        "phase1_meta.json":                  "Phase 1 — Catalog metadata",
        "phase2_enhanced_catalog.json":      "Phase 2 — Enhanced catalog",
        "phase3_validated_chains.json":      "Phase 3 — Chain validation",
        "phase4_vulnerability_report.json":  "Phase 4 — Scoring",
    }
    return {
        fname: {"label": label, "exists": os.path.exists(p(fname)),
                "size": os.path.getsize(p(fname)) if os.path.exists(p(fname)) else 0}
        for fname, label in files.items()
    }


# ── Main route ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    p0   = load_json("phase0_vuln_report.json")
    p0s  = load_json("phase0_static.json")
    p0d  = load_json("phase0_dynamic.json")
    p1   = load_json("phase1_meta.json")
    p1h  = load_json_header("phase1_gadget_catalog.json")
    p2h  = load_json_header("phase2_enhanced_catalog.json")
    p3   = load_json("phase3_validated_chains.json")
    p4   = load_json("phase4_vulnerability_report.json")

    # Trim large arrays for template embedding
    if p3 and "validated_chains" in p3:
        p3 = dict(p3)
        p3["validated_chains"] = p3["validated_chains"][:60]
    if p4 and "top_chains" in p4:
        p4 = dict(p4)
        p4["top_chains"] = p4["top_chains"][:30]

    afl_plot = parse_afl_plot()
    # Downsample plot to at most 300 points
    if afl_plot and len(afl_plot["rows"]) > 300:
        step = len(afl_plot["rows"]) // 300
        afl_plot = dict(afl_plot)
        afl_plot["rows"] = afl_plot["rows"][::step]

    return render_template(
        "index.html",
        cra_dir  = D(),
        pipeline = pipeline_status(),
        p0=p0, p0s=p0s, p0d=p0d,
        p1=p1, p1h=p1h, p2h=p2h,
        p3=p3, p4=p4,
        afl_plot  = afl_plot,
        afl_stats = afl_dir_stats(),
        seeds     = seed_list(),
        md_disasm  = load_text("phase0_disassembly_report.md"),
        md_class   = load_text("phase0_5_vulnerability_report.md"),
        md_handoff = load_text("phase0_handoff_summary.md"),
        p4_txt     = load_text("phase4_vulnerability_report.txt"),
        afl_stderr = load_text("afl_stderr.log", 64_000),
    )


# ── Live-reload API ────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    ps = pipeline_status()
    return jsonify({
        "cra_dir": D(),
        "phases_complete": sum(1 for v in ps.values() if v["exists"]),
        "phases_total":    len(ps),
        "pipeline":        ps,
        "afl":             afl_dir_stats(),
    })


@app.route("/api/setdir", methods=["POST"])
def api_setdir():
    d = request.json.get("dir", "").strip()
    if d and os.path.isdir(d):
        _state["cra_dir"] = d
        return jsonify({"ok": True, "dir": d})
    return jsonify({"ok": False, "error": "Not a directory"}), 400


@app.route("/api/p4chains")
def api_p4chains():
    d = load_json("phase4_vulnerability_report.json") or {}
    return jsonify(d.get("top_chains", [])[:50])


@app.route("/api/p3chains")
def api_p3chains():
    d = load_json("phase3_validated_chains.json") or {}
    return jsonify(d.get("validated_chains", [])[:60])


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = 5000
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--port", "-p") and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif os.path.isdir(args[i]):
            _state["cra_dir"] = args[i]; i += 1
        else:
            i += 1
    print(f"[*] CRA Pipeline Dashboard → http://127.0.0.1:{port}")
    print(f"[*] Data directory : {D()}")
    app.run(debug=False, host="127.0.0.1", port=port, threaded=True)
