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
    """
    Nel repo il file può essere "tutto su una riga" con spazi.
    Inseriamo newline prima di #EXT e prima di http(s) per parsarlo bene.
    """
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


def is_likely_dns_error(ex: Exception) -> bool:
    msg = str(ex).lower()
    return any(
        token in msg
        for token in [
            "name or service not known",
            "failed to resolve",
            "temporary failure in name resolution",
            "nodename nor servname provided",
            "dns",
        ]
    )


def is_timeout_error(ex: Exception) -> bool:
    return isinstance(ex, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)) or "timed out" in str(ex).lower()


def http_get_some(url: str, ua: Optional[str], timeout_s: int, max_bytes: int) -> Tuple[int, str, bytes]:
    headers = {}
    if ua:
        headers["User-Agent"] = ua

    # GET streaming: molti endpoint non gradiscono HEAD
    r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True, stream=True)
    status = r.status_code
    ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    data = b""
    try:
        for chunk in r.iter_content(chunk_size=1024):
            if not chunk:
                break
            data += chunk
            if len(data) >= max_bytes:
                data = data[:max_bytes]
                break
    finally:
        r.close()

    return status, ctype, data


def check_entry(
    e: Entry,
    timeout_s: int,
    retries: int,
    backoff_s: float,
    strict: bool,
) -> Tuple[Status, str]:
    stype = sniff_type(e.url)

    last_ex: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        try:
            status, ctype, data = http_get_some(e.url, e.user_agent, timeout_s=timeout_s, max_bytes=4096)

            # Tipico per stream che funzionano nei player ma bloccano bot/datacenter/cookie
            if status in (403, 451) and not strict:
                return Status.WARN, f"Restricted (HTTP {status})"

            if status < 200 or status >= 400:
                # 5xx a volte flappano: ritenta in modalità non-strict
                if not strict and status >= 500 and attempt < retries:
                    time.sleep(backoff_s * attempt)
                    continue
                return Status.FAIL, f"HTTP {status}"

            head = data.decode("utf-8", errors="ignore")

            if stype == "hls":
                if "#EXTM3U" in head:
                    return Status.OK, "OK (HLS)"
                return Status.FAIL, "Bad HLS content"

            if stype == "dash":
                if "<MPD" in head or "urn:mpeg:dash:schema:mpd" in head:
                    return Status.OK, "OK (DASH)"
                return Status.FAIL, "Bad DASH content"

            return Status.OK, "OK"

        except requests.exceptions.RequestException as ex:
            last_ex = ex

            # Non strict: timeout/dns -> WARN (flaky / dipende dal runner)
            if not strict and (is_timeout_error(ex) or is_likely_dns_error(ex)):
                if attempt < retries:
                    time.sleep(backoff_s * attempt)
                    continue
                kind = "Timeout" if is_timeout_error(ex) else "DNS"
                return Status.WARN, f"{kind} issue"

            if attempt < retries:
                time.sleep(backoff_s * attempt)
                continue

            return Status.FAIL, f"Request error: {type(ex).__name__}"

    return Status.FAIL, f"Request error: {last_ex}"


def build_html(results: List[Tuple[Entry, Status, str]]) -> str:
    ok = sum(1 for _, st, _ in results if st == Status.OK)
    warn = sum(1 for _, st, _ in results if st == Status.WARN)
    fail = sum(1 for _, st, _ in results if st == Status.FAIL)
    total = len(results)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # righe tabella con data-status e testo ricercabile
    rows = []
    for e, st, msg in results:
        stv = st.value
        badge_class = "success" if st == Status.OK else ("warning text-dark" if st == Status.WARN else "danger")
        icon = "✅" if st == Status.OK else ("⚠️" if st == Status.WARN else "❌")

        name_esc = html.escape(e.name)
        msg_esc = html.escape(msg)
        url_esc = html.escape(e.url, quote=True)

        searchable = f"{e.name} {msg} {e.url}".lower()
        rows.append(
            f"""
            <tr data-status="{stv}" data-search="{html.escape(searchable, quote=True)}">
              <td class="text-nowrap">
                <span class="badge bg-{badge_class}">{icon} {stv}</span>
              </td>
              <td class="fw-semibold">{name_esc}</td>
              <td class="text-secondary">{msg_esc}</td>
              <td class="text-end">
                <a class="btn btn-sm btn-outline-light" href="{url_esc}" target="_blank" rel="noreferrer noopener">Apri</a>
              </td>
            </tr>
            """.strip()
        )

    # Bootstrap 5 (CDN) + Bootstrap Icons (CDN)
    return f"""<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>IPTV Italia – Monitor</title>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <style>
    body {{
      background:
        radial-gradient(1200px 600px at 20% 0%, rgba(71,118,230,.25), transparent 60%),
        radial-gradient(900px 500px at 85% 10%, rgba(142,45,226,.20), transparent 55%),
        radial-gradient(1000px 700px at 50% 100%, rgba(0,212,255,.08), transparent 60%),
        #0b1020;
    }}
    .glass {{
      background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.12);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 20px 50px rgba(0,0,0,.35);
    }}
    .subtle-border {{
      border: 1px solid rgba(255,255,255,.10) !important;
    }}
    .table thead th {{
      position: sticky;
      top: 0;
      z-index: 2;
      background: rgba(11,16,32,.92);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border-bottom: 1px solid rgba(255,255,255,.12);
    }}
    .table tbody tr:hover {{
      background: rgba(255,255,255,.04);
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }}
    .muted {{
      color: rgba(255,255,255,.7);
    }}
  </style>
</head>

<body class="text-white">
  <div class="container py-4 py-md-5">
    <div class="glass rounded-4 p-4 p-md-5 mb-4">
      <div class="d-flex flex-column flex-md-row align-items-start align-items-md-center justify-content-between gap-3">
        <div>
          <h1 class="h3 mb-1">IPTV Italia – Stream Monitor</h1>
          <div class="muted small">
            <i class="bi bi-clock"></i> Generato: <span class="mono">{generated}</span>
            <span class="mx-2">•</span>
            <i class="bi bi-collection-play"></i> Totale: <span class="mono">{total}</span>
          </div>
        </div>

        <div class="d-flex gap-2 flex-wrap">
          <span class="badge bg-success-subtle text-success-emphasis subtle-border rounded-pill px-3 py-2">
            <i class="bi bi-check2-circle"></i> OK <span class="mono">({ok})</span>
          </span>
          <span class="badge bg-warning-subtle text-warning-emphasis subtle-border rounded-pill px-3 py-2">
            <i class="bi bi-exclamation-triangle"></i> WARN <span class="mono">({warn})</span>
          </span>
          <span class="badge bg-danger-subtle text-danger-emphasis subtle-border rounded-pill px-3 py-2">
            <i class="bi bi-x-circle"></i> FAIL <span class="mono">({fail})</span>
          </span>
        </div>
      </div>

      <hr class="border-white border-opacity-10 my-4" />

      <div class="row g-3 align-items-end">
        <div class="col-12 col-lg-5">
          <label class="form-label muted small mb-1">Cerca canale / url / messaggio</label>
          <div class="input-group">
            <span class="input-group-text bg-transparent text-white border-white border-opacity-10"><i class="bi bi-search"></i></span>
            <input id="q" type="text" class="form-control bg-transparent text-white border-white border-opacity-10"
                   placeholder="es. LA7, mediaset, 404, m3u8..." autocomplete="off" />
            <button id="clear" class="btn btn-outline-light border-white border-opacity-10" type="button">Reset</button>
          </div>
        </div>

        <div class="col-12 col-lg-5">
          <label class="form-label muted small mb-1">Filtro stato</label>
          <div class="btn-group w-100" role="group" aria-label="Filtro stato">
            <input type="radio" class="btn-check" name="st" id="st_all" value="ALL" checked>
            <label class="btn btn-outline-light border-white border-opacity-10" for="st_all">Tutti</label>

            <input type="radio" class="btn-check" name="st" id="st_ok" value="OK">
            <label class="btn btn-outline-light border-white border-opacity-10" for="st_ok">OK</label>

            <input type="radio" class="btn-check" name="st" id="st_warn" value="WARN">
            <label class="btn btn-outline-light border-white border-opacity-10" for="st_warn">WARN</label>

            <input type="radio" class="btn-check" name="st" id="st_fail" value="FAIL">
            <label class="btn btn-outline-light border-white border-opacity-10" for="st_fail">FAIL</label>
          </div>
        </div>

        <div class="col-12 col-lg-2">
          <!--<label class="form-label muted small mb-1">Visibili</label>-->
          <div class="glass rounded-3 px-3 py-2 text-center">
            <div class="small muted">Stream</div>
            <div class="h5 mb-0 mono" id="visibleCount">0</div>
          </div>
        </div>
      </div>
    </div>

    <div class="glass rounded-4 overflow-hidden">
      <div class="table-responsive" style="max-height: 70vh;">
        <table class="table table-dark table-hover align-middle mb-0">
          <thead>
            <tr>
              <th style="width: 140px;">Stato</th>
              <th>Canale</th>
              <th>Dettaglio</th>
              <th class="text-end" style="width: 120px;">Link</th>
            </tr>
          </thead>
          <tbody id="tbody">
            {''.join(rows)}
          </tbody>
        </table>
      </div>
      <div class="px-3 px-md-4 py-3 border-top border-white border-opacity-10 d-flex flex-column flex-md-row gap-2 justify-content-between">
        <div class="muted small">
          Nota: WARN include spesso <span class="mono">403/451</span>, DNS o timeout tipici dei runner GitHub (stream comunque OK in player reali).
        </div>
        <div class="muted small">
          <i class="bi bi-github"></i> GitHub Pages
        </div>
      </div>
    </div>
  </div>

  <script>
    const q = document.getElementById('q');
    const clearBtn = document.getElementById('clear');
    const tbody = document.getElementById('tbody');
    const visibleCount = document.getElementById('visibleCount');
    const radios = [...document.querySelectorAll('input[name="st"]')];

    function currentFilter() {{
      const r = radios.find(x => x.checked);
      return r ? r.value : "ALL";
    }}

    function applyFilters() {{
      const query = (q.value || "").trim().toLowerCase();
      const filter = currentFilter();

      let visible = 0;
      for (const tr of tbody.querySelectorAll('tr')) {{
        const st = tr.getAttribute('data-status');
        const hay = (tr.getAttribute('data-search') || "");

        const okStatus = (filter === "ALL") || (st === filter);
        const okQuery = (!query) || hay.includes(query);

        const show = okStatus && okQuery;
        tr.style.display = show ? "" : "none";
        if (show) visible++;
      }}
      visibleCount.textContent = String(visible);
    }}

    q.addEventListener('input', applyFilters);
    radios.forEach(r => r.addEventListener('change', applyFilters));
    clearBtn.addEventListener('click', () => {{
      q.value = "";
      document.getElementById('st_all').checked = true;
      applyFilters();
      q.focus();
    }});

    // init
    applyFilters();
  </script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--playlist", default="iptvitalia.m3u")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=1.25)
    ap.add_argument("--strict", action="store_true", help="Treat 403/451 + DNS/timeout as FAIL (no WARN).")
    ap.add_argument("--output", default="site/index.html")
    args = ap.parse_args()

    raw = Path(args.playlist).read_text(encoding="utf-8", errors="ignore")
    entries = parse_entries(normalize_m3u_text(raw))

    if not entries:
        print("No entries found in playlist.", file=sys.stderr)
        return 2

    results: List[Tuple[Entry, Status, str]] = []
    for e in entries:
        st, msg = check_entry(
            e,
            timeout_s=args.timeout,
            retries=args.retries,
            backoff_s=args.backoff,
            strict=args.strict,
        )
        results.append((e, st, msg))
        print(f"{st.value} - {e.name} - {msg}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(results), encoding="utf-8")

    return 1 if any(st == Status.FAIL for _, st, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
