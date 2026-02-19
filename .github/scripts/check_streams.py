#!/usr/bin/env python3
import argparse
import html
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

import requests


class Status(Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class Entry:
    name: str
    url: str
    user_agent: Optional[str] = None


def normalize_m3u_text(raw: str) -> str:
    s = re.sub(r"[ \t]+", " ", raw.replace("\r", "").replace("\n", " ").strip())
    s = re.sub(r" (?=#EXT)", "\n", s)
    s = re.sub(r" (?=https?://)", "\n", s)
    return s + "\n"


def parse_entries(m3u_text: str) -> List[Entry]:
    lines = [ln.strip() for ln in m3u_text.splitlines() if ln.strip()]
    entries: List[Entry] = []
    current_name: Optional[str] = None
    current_ua: Optional[str] = None

    for ln in lines:
        if ln.startswith("#EXTINF:"):
            current_name = ln.split(",", 1)[1].strip() if "," in ln else ln.replace("#EXTINF:", "").strip()
        elif ln.startswith("#EXTVLCOPT:http-user-agent="):
            current_ua = ln.split("=", 1)[1].strip()
        elif ln.startswith("http://") or ln.startswith("https://"):
            entries.append(Entry(name=current_name or "UNKNOWN", url=ln, user_agent=current_ua))
            current_name = None
            current_ua = None

    return entries


def sniff_type(url: str) -> str:
    u = url.lower()
    if ".m3u8" in u:
        return "hls"
    if ".mpd" in u:
        return "dash"
    return "http"


def http_get_some(url: str, ua: Optional[str], timeout_s: int):
    headers = {}
    if ua:
        headers["User-Agent"] = ua

    r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True, stream=True)
    status = r.status_code

    data = b""
    try:
        for chunk in r.iter_content(chunk_size=1024):
            if not chunk:
                break
            data += chunk
            if len(data) >= 4096:
                break
    finally:
        r.close()

    return status, data


def check_entry(e: Entry, timeout_s: int, retries: int, backoff: float) -> Tuple[Status, str]:
    stype = sniff_type(e.url)

    for attempt in range(1, retries + 1):
        try:
            status, data = http_get_some(e.url, e.user_agent, timeout_s)

            if status in (403, 451):
                return Status.WARN, f"Restricted (HTTP {status})"

            if status < 200 or status >= 400:
                if attempt < retries:
                    time.sleep(backoff * attempt)
                    continue
                return Status.FAIL, f"HTTP {status}"

            head = data.decode("utf-8", errors="ignore")

            if stype == "hls" and "#EXTM3U" in head:
                return Status.OK, "OK (HLS)"

            if stype == "dash" and "<MPD" in head:
                return Status.OK, "OK (DASH)"

            return Status.OK, "OK"

        except requests.exceptions.RequestException:
            if attempt < retries:
                time.sleep(backoff * attempt)
                continue
            return Status.WARN, "Network/DNS issue"

    return Status.FAIL, "Unknown error"


def build_html(results: List[Tuple[Entry, Status, str]]) -> str:
    ok = sum(1 for _, s, _ in results if s == Status.OK)
    warn = sum(1 for _, s, _ in results if s == Status.WARN)
    fail = sum(1 for _, s, _ in results if s == Status.FAIL)
    total = len(results)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for e, s, msg in results:
        badge_class = (
            "success" if s == Status.OK
            else "warning text-dark" if s == Status.WARN
            else "danger"
        )
        icon = "✓" if s == Status.OK else "⚠" if s == Status.WARN else "✕"

        safe_name = html.escape(e.name)
        safe_msg = html.escape(msg)
        safe_url = html.escape(e.url, quote=True)

        rows.append(f"""
        <tr class="rowlink" data-status="{s.value}" data-search="{html.escape((e.name + ' ' + msg + ' ' + e.url).lower(), quote=True)}" data-url="{safe_url}">
          <td class="pe-0">
            <span class="badge bg-{badge_class} status-badge">
              <span class="status-dot"></span>
              <span class="status-ico">{icon}</span>
              <span class="status-txt">{s.value}</span>
            </span>
          </td>
          <td class="fw-semibold channel">{safe_name}</td>
          <td class="text-secondary detail">{safe_msg}</td>
          <td class="text-end ps-0">
            <a class="btn btn-sm btn-outline-light btn-open" href="{safe_url}" target="_blank" rel="noreferrer">
              Apri
            </a>
          </td>
        </tr>
        """)

    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPTV Italia – Stream Monitor</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
:root {{
  --bg0:#070A12;
  --bg1:#0B1020;
  --card:rgba(255,255,255,.06);
  --card2:rgba(255,255,255,.085);
  --stroke:rgba(255,255,255,.12);
  --stroke2:rgba(255,255,255,.18);
  --muted:rgba(255,255,255,.65);
}}

html, body {{ height:100%; }}
body {{
  background:
    radial-gradient(1200px 600px at 10% 0%, rgba(99,102,241,.25), transparent 60%),
    radial-gradient(900px 500px at 90% 10%, rgba(16,185,129,.18), transparent 55%),
    radial-gradient(900px 600px at 50% 100%, rgba(236,72,153,.12), transparent 55%),
    linear-gradient(180deg, var(--bg0), var(--bg1));
  color:#fff;
}}

a {{ text-decoration:none; }}

.glass {{
  background:var(--card);
  border:1px solid var(--stroke);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: 0 20px 60px rgba(0,0,0,.35);
}}

.glass-2 {{
  background:var(--card2);
  border:1px solid var(--stroke2);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}}

.appbar {{
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(7,10,18,.65);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid rgba(255,255,255,.08);
}}

.brand-dot {{
  width:10px; height:10px; border-radius:999px;
  background: linear-gradient(135deg, #22c55e, #6366f1);
  box-shadow: 0 0 0 4px rgba(34,197,94,.15);
}}

.kpi {{
  display:flex; gap:12px; flex-wrap:wrap; align-items:center;
}}

.chip {{
  user-select:none;
  cursor:pointer;
  padding:8px 12px;
  border-radius:999px;
  border:1px solid rgba(255,255,255,.14);
  background: rgba(255,255,255,.06);
  display:inline-flex;
  gap:8px;
  align-items:center;
  transition: transform .08s ease, background .15s ease, border-color .15s ease;
}}
.chip:hover {{ transform: translateY(-1px); background: rgba(255,255,255,.085); border-color: rgba(255,255,255,.22); }}
.chip.active {{ background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.30); }}

.chip .pill {{
  min-width:34px;
  text-align:center;
  padding:2px 8px;
  border-radius:999px;
  font-weight:700;
  background: rgba(255,255,255,.10);
}}

.status-badge {{
  width:124px;
  display:inline-flex;
  justify-content:flex-start;
  align-items:center;
  gap:8px;
  padding:8px 10px;
  border-radius:999px;
}}

.status-dot {{
  width:8px; height:8px; border-radius:999px;
  background: rgba(255,255,255,.9);
  opacity:.9;
}}

.status-ico {{ font-weight:900; }}
.status-txt {{ font-weight:800; letter-spacing:.3px; }}

.table-wrap {{
  max-height: 70vh;
  border-radius: 18px;
  overflow: hidden;
}}

.table {{
  margin:0;
}}
.table thead th {{
  position: sticky;
  top: 0;
  z-index: 2;
  background: rgba(11,16,32,.92) !important;
  border-bottom: 1px solid rgba(255,255,255,.10);
}}

.table-dark {{
  --bs-table-bg: transparent;
  --bs-table-striped-bg: rgba(255,255,255,.03);
  --bs-table-hover-bg: rgba(255,255,255,.05);
  --bs-table-border-color: rgba(255,255,255,.08);
}}

.rowlink {{
  cursor: pointer;
}}
.rowlink:active {{
  transform: scale(.999);
}}

.channel {{
  max-width: 420px;
}}
.detail {{
  max-width: 520px;
}}
.channel, .detail {{
  overflow:hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

.form-control {{
  border-radius: 14px;
  padding: 10px 12px;
}}
.form-control:focus {{
  box-shadow: 0 0 0 .25rem rgba(99,102,241,.18);
  border-color: rgba(99,102,241,.55) !important;
}}

.btn-open {{
  border-radius: 12px;
}}

.footer {{
  color: var(--muted);
}}

kbd {{
  background: rgba(255,255,255,.10);
  border: 1px solid rgba(255,255,255,.10);
  border-bottom-width: 2px;
}}
</style>
</head>

<body>

<div class="appbar">
  <div class="container py-3">
    <div class="d-flex align-items-center justify-content-between gap-3 flex-wrap">
      <div class="d-flex align-items-center gap-3">
        <span class="brand-dot"></span>
        <div>
          <div class="h5 mb-0">IPTV Italia – Stream Monitor</div>
          <div class="small text-secondary">Generato: {generated} · Totale: {total}</div>
        </div>
      </div>

      <div class="d-flex align-items-center gap-2 flex-wrap">
        <div class="small text-secondary d-none d-md-block">
          Filtra: <kbd>OK</kbd> <kbd>WARN</kbd> <kbd>FAIL</kbd> · Cerca per nome/URL
        </div>
      </div>
    </div>
  </div>
</div>

<div class="container py-4">

  <div class="glass rounded-4 p-3 p-md-4 mb-3">
    <div class="d-flex gap-3 flex-wrap align-items-center justify-content-between">
      <div class="kpi">
        <span class="chip active" data-filter="ALL" title="Mostra tutti">
          Tutti <span class="pill">{total}</span>
        </span>
        <span class="chip" data-filter="OK" title="Mostra solo OK">
          ✅ OK <span class="pill">{ok}</span>
        </span>
        <span class="chip" data-filter="WARN" title="Mostra solo WARN">
          ⚠️ WARN <span class="pill">{warn}</span>
        </span>
        <span class="chip" data-filter="FAIL" title="Mostra solo FAIL">
          ❌ FAIL <span class="pill">{fail}</span>
        </span>
      </div>

      <div class="d-flex gap-2 align-items-center flex-wrap">
        <input id="q" class="form-control bg-dark text-white border-secondary"
               style="min-width:260px;"
               placeholder="Cerca canale, dettaglio o URL… (es. rai, sky, m3u8)">
        <button id="clear" class="btn btn-outline-light" type="button">Reset</button>
      </div>
    </div>
  </div>

  <div class="glass rounded-4 p-2 p-md-3">
    <div class="table-wrap glass-2">
      <div class="table-responsive">
        <table class="table table-dark table-hover align-middle">
          <thead>
            <tr>
              <th style="width:140px;">Stato</th>
              <th>Canale</th>
              <th>Dettaglio</th>
              <th class="text-end" style="width:110px;">Link</th>
            </tr>
          </thead>
          <tbody id="tbody">
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    </div>

    <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mt-3 px-2">
      <div class="footer small">
        Tip: clicca una riga per aprire il link · <span id="shown"></span>
      </div>
      <div class="footer small">
        Exit code = 1 se esiste almeno un FAIL
      </div>
    </div>
  </div>

</div>

<script>
const q = document.getElementById('q');
const clearBtn = document.getElementById('clear');
const tbody = document.getElementById('tbody');
const allRows = Array.from(document.querySelectorAll('#tbody tr'));
const chips = Array.from(document.querySelectorAll('.chip'));
const shown = document.getElementById('shown');

let activeFilter = "ALL";

function applyFilters() {{
  const val = (q.value || "").toLowerCase().trim();

  let visible = 0;
  for (const r of allRows) {{
    const hay = r.dataset.search || "";
    const st = r.dataset.status || "";
    const matchesText = !val || hay.includes(val);
    const matchesStatus = (activeFilter === "ALL") || (st === activeFilter);
    const show = matchesText && matchesStatus;
    r.style.display = show ? "" : "none";
    if (show) visible++;
  }}

  shown.textContent = `Visualizzati: ${visible} / {total}`;
}}

function setActiveChip(filter) {{
  activeFilter = filter;
  chips.forEach(c => c.classList.toggle('active', (c.dataset.filter === filter)));
  applyFilters();
}}

q.addEventListener('input', applyFilters);

clearBtn.addEventListener('click', () => {{
  q.value = "";
  setActiveChip("ALL");
}});

chips.forEach(c => {{
  c.addEventListener('click', () => setActiveChip(c.dataset.filter));
}});

// Shortcut da tastiera: o/w/f per filtrare, ESC per reset
document.addEventListener('keydown', (e) => {{
  if (e.key === "Escape") {{
    q.value = "";
    setActiveChip("ALL");
  }}
  if (e.target && (e.target.tagName || "").toLowerCase() === "input") return;

  const k = (e.key || "").toLowerCase();
  if (k === "o") setActiveChip("OK");
  if (k === "w") setActiveChip("WARN");
  if (k === "f") setActiveChip("FAIL");
}});

// Righe cliccabili (senza interferire col bottone)
tbody.addEventListener('click', (e) => {{
  const a = e.target.closest('a');
  if (a) return;

  const tr = e.target.closest('tr');
  if (!tr) return;

  const url = tr.dataset.url;
  if (url) window.open(url, "_blank", "noopener,noreferrer");
}});

applyFilters();
</script>

</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playlist", default="iptvitalia.m3u")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=1.2)
    ap.add_argument("--output", default="site/index.html")
    args = ap.parse_args()

    raw = Path(args.playlist).read_text(encoding="utf-8", errors="ignore")
    entries = parse_entries(normalize_m3u_text(raw))

    results = []
    for e in entries:
        status, msg = check_entry(e, args.timeout, args.retries, args.backoff)
        results.append((e, status, msg))
        print(status.value, "-", e.name)

    html_content = build_html(results)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8")

    return 1 if any(s == Status.FAIL for _, s, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
