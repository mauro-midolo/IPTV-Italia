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


def is_likely_dns_error(ex: Exception) -> bool:
    msg = str(ex).lower()
    return any(
        token in msg
        for token in [
            "name or service not known",
            "failed to resolve",
            "temporary failure in name resolution",
            "dns",
        ]
    )


def is_timeout_error(ex: Exception) -> bool:
    return isinstance(ex, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)) or "timed out" in str(ex).lower()


def http_get_some(url: str, ua: Optional[str], timeout_s: int, max_bytes: int):
    headers = {}
    if ua:
        headers["User-Agent"] = ua

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
                break
    finally:
        r.close()

    return status, ctype, data


def check_entry(e: Entry, timeout_s: int, retries: int, strict: bool) -> Tuple[Status, str]:
    stype = sniff_type(e.url)

    for attempt in range(retries):
        try:
            status, ctype, data = http_get_some(e.url, e.user_agent, timeout_s, 4096)

            if status in (403, 451) and not strict:
                return Status.WARN, f"Restricted (HTTP {status})"

            if status < 200 or status >= 400:
                return Status.FAIL, f"HTTP {status}"

            head = data.decode("utf-8", errors="ignore")

            if stype == "hls" and "#EXTM3U" in head:
                return Status.OK, "OK (HLS)"

            if stype == "dash" and ("<MPD" in head or "urn:mpeg:dash:schema:mpd" in head):
                return Status.OK, "OK (DASH)"

            return Status.OK, "OK"

        except requests.exceptions.RequestException as ex:
            if not strict and (is_timeout_error(ex) or is_likely_dns_error(ex)):
                return Status.WARN, "Network/DNS issue"

            if attempt == retries - 1:
                return Status.FAIL, "Request error"

            time.sleep(1)

    return Status.FAIL, "Request error"


def build_html(results: List[Tuple[Entry, Status, str]]) -> str:
    ok = sum(1 for _, s, _ in results if s == Status.OK)
    warn = sum(1 for _, s, _ in results if s == Status.WARN)
    fail = sum(1 for _, s, _ in results if s == Status.FAIL)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for e, s, msg in results:
        icon = "✅" if s == Status.OK else ("⚠️" if s == Status.WARN else "❌")
        rows.append(
            f"<tr>"
            f"<td>{icon}</td>"
            f"<td>{html.escape(e.name)}</td>"
            f"<td>{html.escape(msg)}</td>"
            f"<td><a href='{html.escape(e.url)}' target='_blank'>link</a></td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>IPTV Italia Monitor</title>
<style>
body {{ font-family: system-ui; margin:40px; }}
table {{ border-collapse: collapse; width:100%; }}
td,th {{ padding:8px; border-bottom:1px solid #ddd; }}
th {{ text-align:left; }}
</style>
</head>
<body>
<h1>IPTV Italia – Stream Monitor</h1>
<p>Generated: {generated}</p>
<p>OK: {ok} | WARN: {warn} | FAIL: {fail}</p>
<table>
<tr><th></th><th>Channel</th><th>Status</th><th>URL</th></tr>
{''.join(rows)}
</table>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playlist", default="iptvitalia.m3u")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--output", default="site/index.html")
    args = ap.parse_args()

    raw = Path(args.playlist).read_text(encoding="utf-8", errors="ignore")
    entries = parse_entries(normalize_m3u_text(raw))

    results = []
    for e in entries:
        status, msg = check_entry(e, args.timeout, args.retries, args.strict)
        results.append((e, status, msg))
        print(status.value, "-", e.name)

    html_content = build_html(results)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8")

    return 1 if any(s == Status.FAIL for _, s, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
