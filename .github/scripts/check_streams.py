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


def check_entry(e: Entry, timeout_s: int) -> Tuple[Status, str]:
    stype = sniff_type(e.url)

    try:
        status, data = http_get_some(e.url, e.user_agent, timeout_s)

        if status in (403, 451):
            return Status.WARN, f"Restricted (HTTP {status})"

        if status < 200 or status >= 400:
            return Status.FAIL, f"HTTP {status}"

        head = data.decode("utf-8", errors="ignore")

        if stype == "hls" and "#EXTM3U" in head:
            return Status.OK, "OK (HLS)"

        if stype == "dash" and "<MPD" in head:
            return Status.OK, "OK (DASH)"

        return Status.OK, "OK"

    except requests.exceptions.RequestException:
        return Status.WARN, "Network/DNS issue"


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

        rows.append(f"""
        <tr data-status="{s.value}" data-search="{html.escape((e.name + msg + e.url).lower(), quote=True)}">
          <td>
            <span class="badge bg-{badge_class} status-badge">
              {icon} {s.value}
            </span>
          </td>
          <td class="fw-semibold">{html.escape(e.name)}</td>
          <td class="text-secondary">{html.escape(msg)}</td>
          <td class="text-end">
            <a class="btn btn-sm btn-outline-light" href="{html.escape(e.url)}" target="_blank">Apri</a>
          </td>
        </tr>
        """)

    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPTV Italia – Monitor</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body {{
  background:#0b1020;
  color:white;
}}

.glass {{
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.12);
  backdrop-filter:blur(10px);
}}

.status-badge {{
  width:110px;
  display:inline-flex;
  justify-content:center;
  align-items:center;
  gap:6px;
}}

.table thead th {{
  position:sticky;
  top:0;
  background:#0b1020;
}}

</style>
</head>

<body>
<div class="container py-5">

<div class="glass rounded-4 p-4 mb-4">
  <h1 class="h3 mb-3">IPTV Italia – Stream Monitor</h1>
  <div class="mb-2 small text-secondary">
    Generato: {generated} | Totale: {total}
  </div>

  <div class="d-flex gap-3 flex-wrap">
    <span class="badge bg-success-subtle text-success-emphasis">OK: {ok}</span>
    <span class="badge bg-warning-subtle text-warning-emphasis">WARN: {warn}</span>
    <span class="badge bg-danger-subtle text-danger-emphasis">FAIL: {fail}</span>
  </div>
</div>

<div class="glass rounded-4 p-3">
  <input id="q" class="form-control mb-3 bg-dark text-white border-secondary"
         placeholder="Cerca canale...">

  <div class="table-responsive" style="max-height:70vh;">
    <table class="table table-dark table-hover align-middle mb-0">
      <thead>
        <tr>
          <th style="width:130px;">Stato</th>
          <th>Canale</th>
          <th>Dettaglio</th>
          <th class="text-end" style="width:100px;">Link</th>
        </tr>
      </thead>
      <tbody id="tbody">
        {''.join(rows)}
      </tbody>
    </table>
  </div>
</div>

</div>

<script>
const q = document.getElementById('q');
const rows = document.querySelectorAll('#tbody tr');

q.addEventListener('input', () => {{
  const val = q.value.toLowerCase();
  rows.forEach(r => {{
    const hay = r.dataset.search;
    r.style.display = hay.includes(val) ? '' : 'none';
  }});
}});
</script>

</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playlist", default="iptvitalia.m3u")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--output", default="site/index.html")
    args = ap.parse_args()

    raw = Path(args.playlist).read_text(encoding="utf-8", errors="ignore")
    entries = parse_entries(normalize_m3u_text(raw))

    results = []
    for e in entries:
        status, msg = check_entry(e, args.timeout)
        results.append((e, status, msg))
        print(status.value, "-", e.name)

    html_content = build_html(results)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8")

    return 1 if any(s == Status.FAIL for _, s, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
