#!/usr/bin/env python3
import argparse
import re
import sys
import time
from dataclasses import dataclass
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
    # requests/urllib3 usa messaggi diversi a seconda della versione
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

            # 403/451: spesso “funziona nel player” ma blocca bot/datacenter/cookie
            if status in (403, 451) and not strict:
                return Status.WARN, f"RESTRICTED_HTTP_{status} ({ctype or 'no-ctype'})"

            # altri status non OK
            if status < 200 or status >= 400:
                # se non strict, alcuni 5xx possono essere “flaky”: ritenta
                if not strict and status >= 500 and attempt < retries:
                    time.sleep(backoff_s * attempt)
                    continue
                return Status.FAIL, f"HTTP_{status} ({ctype or 'no-ctype'})"

            head = data.decode("utf-8", errors="ignore")

            if stype == "hls":
                if "#EXTM3U" in head:
                    return Status.OK, f"OK (HLS, {ctype or 'no-ctype'})"
                return Status.FAIL, f"BAD_HLS_CONTENT (HTTP_{status})"

            if stype == "dash":
                if "<MPD" in head or "urn:mpeg:dash:schema:mpd" in head:
                    return Status.OK, f"OK (DASH, {ctype or 'no-ctype'})"
                return Status.FAIL, f"BAD_DASH_CONTENT (HTTP_{status})"

            return Status.OK, f"OK (HTTP_{status}, {ctype or 'no-ctype'})"

        except requests.exceptions.RequestException as ex:
            last_ex = ex

            # Se non strict: timeout/DNS => WARN (flaky / dipende dal runner)
            if not strict and (is_timeout_error(ex) or is_likely_dns_error(ex)):
                # ritenta un paio di volte prima di decidere WARN
                if attempt < retries:
                    time.sleep(backoff_s * attempt)
                    continue
                kind = "TIMEOUT" if is_timeout_error(ex) else "DNS"
                return Status.WARN, f"{kind}_ERROR: {ex}"

            # altre eccezioni: ritenta, poi FAIL
            if attempt < retries:
                time.sleep(backoff_s * attempt)
                continue
            return Status.FAIL, f"REQUEST_ERROR: {ex}"

    # fallback
    return Status.FAIL, f"REQUEST_ERROR: {last_ex}"


def write_report(path: Path, results: List[Tuple[Entry, Status, str]]) -> None:
    ok = sum(1 for _, st, _ in results if st == Status.OK)
    warn = sum(1 for _, st, _ in results if st == Status.WARN)
    fail = sum(1 for _, st, _ in results if st == Status.FAIL)

    out: List[str] = []
    out.append("# IPTV stream check report\n\n")
    out.append(f"- Total: **{len(results)}**\n")
    out.append(f"- OK: **{ok}**\n")
    out.append(f"- WARN (restricted/flaky): **{warn}**\n")
    out.append(f"- FAIL: **{fail}**\n\n")
    out.append("---\n\n")

    if fail:
        out.append("## ❌ FAIL streams\n\n")
        for e, st, msg in results:
            if st == Status.FAIL:
                out.append(f"- **{e.name}**\n  - URL: `{e.url}`\n  - Result: `{msg}`\n")
        out.append("\n---\n\n")

    if warn:
        out.append("## ⚠️ WARN streams (likely OK in real players / flaky)\n\n")
        for e, st, msg in results:
            if st == Status.WARN:
                out.append(f"- **{e.name}**\n  - URL: `{e.url}`\n  - Result: `{msg}`\n")
        out.append("\n---\n\n")

    out.append("## All streams\n\n")
    for e, st, msg in results:
        icon = "✅" if st == Status.OK else ("⚠️" if st == Status.WARN else "❌")
        out.append(f"- {icon} **{e.name}** — `{msg}`\n  - `{e.url}`\n")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(out), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--playlist", default="iptvitalia.m3u")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=1.25)
    ap.add_argument("--report", default="stream-check/report.md")
    ap.add_argument("--strict", action="store_true", help="Treat 403/451 + DNS/timeout as FAIL (no WARN).")
    args = ap.parse_args()

    raw = Path(args.playlist).read_text(encoding="utf-8", errors="ignore")
    norm = normalize_m3u_text(raw)
    entries = parse_entries(norm)

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
        label = st.value
        print(f"{label} - {e.name} - {msg}")

    write_report(Path(args.report), results)

    # FAIL solo se ci sono FAIL veri
    return 1 if any(st == Status.FAIL for _, st, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
