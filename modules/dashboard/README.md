# CRA Framework — Full Pipeline Dashboard

A single-page Flask dashboard that reads every file produced by the CRA
pipeline (`cra_output/`) and visualises them across seven tabs.

## Quick start

```bash
pip install flask
python app.py ./cra_output        # explicit path (default: ./cra_output)
python app.py --port 8080         # custom port
```

Open **http://127.0.0.1:5000** in any browser.

---

## Tabs

| Tab | Data source(s) | Key visuals |
|-----|----------------|-------------|
| **Overview** | All phases | Pipeline health row · key metric tiles · mitigation grid · best chain |
| **Binary** | `phase0_static.json` `phase0_vuln_report.json` | Metadata · security properties · vulnerability pattern table · function & section tables |
| **Gadgets** | `phase1_meta.json` `phase1_gadget_catalog.json` `phase2_enhanced_catalog.json` | Sink-type donut · semantic-tag bar chart · Phase 2 stats |
| **Chains** | `phase3_validated_chains.json` | Validation-outcome donut · best-chain detail · filterable sortable chain table |
| **Scoring** | `phase4_vulnerability_report.json` | Severity donut · mitigation-multiplier breakdown · scored top-chain table |
| **AFL++** | `afl_output/default/plot_data` `afl_stderr.log` | Execs/sec line chart · crashes+corpus over time · seed corpus table |
| **Reports** | `phase0_disassembly_report.md` `phase0_5_vulnerability_report.md` `phase0_handoff_summary.md` `phase4_vulnerability_report.txt` `afl_stderr.log` | Rendered markdown · raw text log viewer |

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard |
| `GET` | `/api/status` | Pipeline file status + AFL++ dir counts |
| `POST` | `/api/setdir` | Switch `cra_output` directory without restart |
| `GET` | `/api/p3chains` | Top 60 Phase 3 validated chains (JSON) |
| `GET` | `/api/p4chains` | Top 50 Phase 4 scored chains (JSON) |

The dashboard polls `/api/status` every 12 s and updates the status dot
in the top-right corner when new phases complete.

---

## Large-file handling

`phase1_gadget_catalog.json` and `phase2_enhanced_catalog.json` can each be
hundreds of MB.  The backend streams only the metadata header of each file
(stopping at the `"gadgets"` array line) so the page loads instantly
regardless of catalog size.

---

## Notes

- All CDN assets (Chart.js 4.4.1, markdown-it 14.1.0, Google Fonts) are
  loaded from `cdnjs.cloudflare.com` / `fonts.googleapis.com`.  An internet
  connection is required for first load; after that the browser caches them.
- The dashboard is read-only; it never writes to `cra_output/`.
- Phase 3 / Phase 4 arrays are trimmed to 60 / 30 entries for embedding;
  the full data remains on disk and is served via the `/api/*` endpoints.
