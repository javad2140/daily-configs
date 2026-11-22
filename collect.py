# -*- coding: utf-8 -*-
"""
collect.py (version 2)

Collects free proxy configs from:
  1) PUBLIC Telegram channel web pages (https://t.me/s/<channel>)  -> channels.txt
  2) Raw subscription files hosted on GitHub                         -> sources.txt

Pipeline:
  - sanitize + remove duplicates
  - TCP check (drops servers whose port does not answer from this machine)
  - real connection test with xray-knife (delay), then speed test on the best ones
  - writes sub.txt (plain, with Hiddify header lines), sub_b64.txt and report.txt

If xray-knife is missing or fails, the script falls back to the TCP-only list.
Needs only the Python standard library (plus the xray-knife binary for the real test).
"""

import base64
import csv
import datetime
import html
import io
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ----------------------------- SETTINGS -----------------------------

BASE_DIR = Path(__file__).resolve().parent
CHANNELS_FILE = BASE_DIR / "channels.txt"
SOURCES_FILE = BASE_DIR / "sources.txt"
OUT_PLAIN = BASE_DIR / "sub.txt"
OUT_B64 = BASE_DIR / "sub_b64.txt"
OUT_REPORT = BASE_DIR / "report.txt"
WORK_DIR = BASE_DIR / "work"

PROFILE_TITLE = "Daily Configs"   # name shown in Hiddify
UPDATE_INTERVAL_HOURS = 6         # how often Hiddify re-downloads the file

MAX_AGE_HOURS = 48                # Telegram: ignore posts older than this
PAGES_PER_CHANNEL = 5             # Telegram: pages (about 20 posts each) per channel
CHANNEL_CAP = 300                 # max links taken from one Telegram channel
SOURCE_CAP = 600                  # max links taken (random sample) from one GitHub file
MAX_CANDIDATES = 2500             # max servers sent to the real test
MAX_LINKS = 400                   # max links written to sub.txt

REMOVE_DEAD = True                # drop servers whose port does not answer
TCP_TIMEOUT = 4.0
MAX_WORKERS = 100

# Real test (xray-knife). The workflow sets XRAY_KNIFE_BIN to the downloaded binary.
XRAY_KNIFE = os.environ.get("XRAY_KNIFE_BIN", "xray-knife")
REAL_TEST_ENABLED = True
REAL_TEST_THREADS = 60
REAL_TEST_MAX_DELAY_MS = 3000
REAL_TEST_TIMEOUT_SEC = 25 * 60
SPEED_TEST_ENABLED = True
SPEED_TEST_TOP = 40
SPEED_TEST_THREADS = 4
SPEED_TEST_TIMEOUT_SEC = 15 * 60

FINAL_VERIFIED_MAX = 25           # max verified servers kept (best first)
EXTRA_UNVERIFIED = 0              # extra servers that passed only the TCP check
FALLBACK_MAX = 30                 # list size if the real test could not run

REQUEST_DELAY = 1.0               # seconds between Telegram page requests
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# UDP-based protocols cannot be checked with a TCP test, so they are kept as they are.
UDP_SCHEMES = {"hysteria2", "hy2", "tuic"}

# --------------------------------------------------------------------

LINK_REGEX = re.compile(
    r"(?<![A-Za-z0-9])(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s<>\"']+",
    re.IGNORECASE,
)

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def log(message):
    print(time.strftime("[%H:%M:%S] ") + message, flush=True)


def maybe_b64decode(value):
    compact = re.sub(r"\s+", "", value.strip())
    if not compact:
        return None
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact).decode("utf-8", errors="ignore")
    except Exception:
        return None


def fetch(url, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8-sig", errors="ignore")


def html_to_text(chunk):
    chunk = re.sub(r"<br\s*/?>", "\n", chunk, flags=re.IGNORECASE)
    chunk = re.sub(r"</(?:code|pre|p|div)>", "\n", chunk, flags=re.IGNORECASE)
    chunk = re.sub(r"<[^>]+>", "", chunk)
    return html.unescape(chunk)


def parse_page(page_html):
    messages = []
    chunks = page_html.split("tgme_widget_message_wrap")[1:]
    for chunk in chunks:
        post = re.search(r'data-post="[^"/]+/(\d+)"', chunk)
        if not post:
            continue
        message_id = int(post.group(1))
        timestamp = None
        when = re.search(r'<time[^>]*datetime="([^"]+)"', chunk)
        if when:
            try:
                timestamp = datetime.datetime.fromisoformat(when.group(1))
            except ValueError:
                timestamp = None
        messages.append((message_id, timestamp, html_to_text(chunk)))
    return messages


def clean_link(link):
    return link.strip().rstrip(".,;")


def collect_channel(channel, cutoff):
    found = []
    before = None
    for _ in range(PAGES_PER_CHANNEL):
        url = "https://t.me/s/%s" % channel
        if before:
            url += "?before=%d" % before
        try:
            page = fetch(url)
        except Exception as error:
            log("  could not read %s: %s" % (channel, error))
            break

        messages = parse_page(page)
        if not messages:
            if before is None:
                log("  no public posts found for %s (channel may not allow web preview)" % channel)
            break

        reached_old_posts = False
        for message_id, timestamp, text in messages:
            if timestamp is not None and timestamp < cutoff:
                reached_old_posts = True
                continue
            for link in LINK_REGEX.findall(text):
                found.append((timestamp or EPOCH, clean_link(link)))

        oldest_id = min(message[0] for message in messages)
        if reached_old_posts or oldest_id <= 1 or (before is not None and oldest_id >= before):
            break
        before = oldest_id
        time.sleep(REQUEST_DELAY)
    return found


def extract_links(text):
    found = LINK_REGEX.findall(text)
    if found:
        return found
    decoded = maybe_b64decode(text)
    if decoded:
        found = LINK_REGEX.findall(decoded)
        if found:
            return found
    clean_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("#", "//"))
    ]
    if clean_lines:
        decoded = maybe_b64decode("".join(clean_lines))
        if decoded:
            found = LINK_REGEX.findall(decoded)
            if found:
                return found
        collected = []
        for line in clean_lines:
            decoded_line = maybe_b64decode(line)
            if decoded_line:
                collected.extend(LINK_REGEX.findall(decoded_line))
        return collected
    return []


def valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def parse_host_port(link):
    scheme = link.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            body = link[len("vmess://"):].split("#")[0]
            decoded = maybe_b64decode(body)
            if not decoded:
                return None
            data = json.loads(decoded)
            host = str(data.get("add", "")).strip()
            port = valid_port(data.get("port"))
            return (host, port) if host and port else None

        parts = urllib.parse.urlsplit(link)
        try:
            host = parts.hostname
            port = parts.port
        except ValueError:
            host, port = None, None
        if host and port:
            return host, port

        if scheme == "ss":
            raw = link[len("ss://"):].split("#")[0].split("?")[0]
            decoded = maybe_b64decode(raw)
            if decoded and "@" in decoded:
                host_port = decoded.rsplit("@", 1)[1]
                host, _, port_text = host_port.rpartition(":")
                port = valid_port(port_text)
                host = host.strip("[]")
                return (host, port) if host and port else None
    except Exception:
        return None
    return None


def tcp_alive(host, port):
    try:
        connection = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
        connection.close()
        return True
    except Exception:
        return False


def read_channels():
    if not CHANNELS_FILE.exists():
        return []
    channels = []
    for line in CHANNELS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("?")[0].rstrip("/").split("/")[-1].lstrip("@").strip()
        if name and name not in channels:
            channels.append(name)
    return channels


def read_sources():
    if not SOURCES_FILE.exists():
        return []
    sources = []
    for line in SOURCES_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("http://", "https://")) and line not in sources:
            sources.append(line)
    return sources


def sanitize_link(link):
    link = re.sub(r"[\x00-\x20\x7f]", "", link)
    if not link or len(link) > 4000:
        return None
    if "#" in link:
        base, fragment = link.split("#", 1)
        if len(fragment) > 80:
            scheme = base.split("://", 1)[0].lower()
            host_port = parse_host_port(base)
            if host_port:
                label = "%s-%s-%s" % (scheme, host_port[0], host_port[1])
                link = base + "#" + urllib.parse.quote(label, safe="-._")
            else:
                link = base
    return link


def unique_links(links):
    result = []
    seen = set()
    for link in links:
        key = link.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        result.append(link)
    return result


def filter_alive(links):
    checks = []
    keep_without_test = set()
    for link in links:
        scheme = link.split("://", 1)[0].lower()
        if scheme in UDP_SCHEMES:
            keep_without_test.add(link)
            continue
        host_port = parse_host_port(link)
        if host_port:
            checks.append((link, host_port[0], host_port[1]))

    alive = set(keep_without_test)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(tcp_alive, host, port): link for link, host, port in checks}
        for future in as_completed(futures):
            if future.result():
                alive.add(futures[future])

    result = [link for link in links if link in alive]
    log("After removing dead servers: %d of %d links" % (len(result), len(links)))
    return result


def knife_available():
    return bool(shutil.which(XRAY_KNIFE) or os.path.isfile(XRAY_KNIFE))


def run_knife(args, cwd, timeout):
    command = [XRAY_KNIFE] + args
    log("Running: %s" % " ".join(command))
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        log("xray-knife was not found.")
        return False
    except subprocess.TimeoutExpired:
        log("xray-knife timed out after %d seconds." % timeout)
        return False
    except Exception as error:
        log("xray-knife could not run: %s" % error)
        return False

    lines = (completed.stdout or "").splitlines()
    for line in lines[-12:]:
        log("  | " + line[:200])
    log("xray-knife exit code: %d" % completed.returncode)
    return completed.returncode == 0


def run_real_test(candidates):
    if not knife_available():
        log("xray-knife is not installed. Skipping the real test.")
        return []

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    (WORK_DIR / "candidates.txt").write_text("\n".join(candidates), encoding="utf-8")

    attempts = [
        ["http", "-f", "candidates.txt", "-t", str(REAL_TEST_THREADS), "-d", str(REAL_TEST_MAX_DELAY_MS)],
        ["http", "-f", "candidates.txt"],
    ]
    for args in attempts:
        for old_file in WORK_DIR.glob("valid*.txt"):
            old_file.unlink()
        run_knife(args, WORK_DIR, REAL_TEST_TIMEOUT_SEC)
        for valid_file in sorted(WORK_DIR.glob("valid*.txt")):
            text = valid_file.read_text(encoding="utf-8", errors="ignore")
            links = unique_links([clean_link(link) for link in LINK_REGEX.findall(text)])
            if links:
                log("Real test passed: %d servers (fastest first)." % len(links))
                return links
        log("This attempt gave no usable result.")
    return []


def read_speed_csv(directory):
    rows = []
    for path in sorted(directory.glob("*.csv")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace").replace("\x00", "")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                clean = {str(key).strip().lower(): (value or "").strip() for key, value in row.items() if key}
                link = clean.get("link", "")
                status = clean.get("status", "").lower()
                if not link or status != "passed" or not LINK_REGEX.match(link):
                    continue
                try:
                    download = float(clean.get("download", "0") or 0)
                except ValueError:
                    download = 0.0
                try:
                    delay = float(clean.get("delay", "0") or 0)
                except ValueError:
                    delay = 0.0
                rows.append((link, download, delay))
        except Exception as error:
            log("Could not read %s: %s" % (path.name, error))
    return rows


def run_speed_test(top_links):
    if not top_links or not knife_available():
        return []

    speed_dir = WORK_DIR / "speed"
    if speed_dir.exists():
        shutil.rmtree(speed_dir)
    speed_dir.mkdir(parents=True, exist_ok=True)
    (speed_dir / "top.txt").write_text("\n".join(top_links), encoding="utf-8")

    attempts = [
        ["http", "-f", "top.txt", "-S", "-t", str(SPEED_TEST_THREADS), "-x", "csv", "-o", "speed.csv"],
        ["http", "-f", "top.txt", "--speedtest", "-t", str(SPEED_TEST_THREADS), "-x", "csv"],
    ]
    for args in attempts:
        run_knife(args, speed_dir, SPEED_TEST_TIMEOUT_SEC)
        results = read_speed_csv(speed_dir)
        if results:
            log("Speed test finished for %d servers." % len(results))
            return results
        log("This speed test attempt gave no usable result.")
    return []


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    channels = read_channels()
    sources = read_sources()
    if not channels and not sources:
        log("channels.txt and sources.txt are both empty. Add at least one entry, then run again.")
        sys.exit(1)

    report = []
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=MAX_AGE_HOURS)

    telegram_items = []
    for channel in channels:
        items = collect_channel(channel, cutoff)
        items.sort(key=lambda item: item[0], reverse=True)
        items = items[:CHANNEL_CAP]
        log("%s: %d links" % (channel, len(items)))
        report.append("telegram %s: %d links" % (channel, len(items)))
        telegram_items.extend(items)
        time.sleep(REQUEST_DELAY)
    telegram_items.sort(key=lambda item: item[0], reverse=True)
    raw_links = [link for _, link in telegram_items]

    for url in sources:
        short_name = "/".join(url.split("/")[3:5]) + "/" + url.rstrip("/").split("/")[-1]
        try:
            links = extract_links(fetch(url, timeout=90))
        except Exception as error:
            log("Could not fetch %s: %s" % (short_name, error))
            report.append("source %s: FAILED" % short_name)
            continue
        total = len(links)
        if total > SOURCE_CAP:
            links = random.sample(links, SOURCE_CAP)
        log("%s: %d links (using %d)" % (short_name, total, len(links)))
        report.append("source %s: %d links (using %d)" % (short_name, total, len(links)))
        raw_links.extend(links)

    cleaned = []
    for link in raw_links:
        fixed = sanitize_link(link)
        if fixed:
            cleaned.append(fixed)
    unique = unique_links(cleaned)
    log("Total unique links: %d" % len(unique))

    if not unique:
        log("Nothing collected. Keeping the previous files untouched.")
        return

    alive_links = filter_alive(unique) if REMOVE_DEAD else unique
    if not alive_links:
        log("Every server looked dead. Keeping the previous files untouched.")
        return
    alive_links = alive_links[:MAX_CANDIDATES]

    verified = run_real_test(alive_links) if REAL_TEST_ENABLED else []
    speed_results = []
    method = "TCP check only (real test did not run)"

    if verified:
        method = "real test"
        if SPEED_TEST_ENABLED:
            speed_results = run_speed_test(verified[:SPEED_TEST_TOP])
        by_speed = [
            link
            for link, download, _ in sorted(
                (row for row in speed_results if row[1] > 0), key=lambda row: row[1], reverse=True
            )
        ]
        if by_speed:
            method = "real test + speed test"
        ordered = unique_links(by_speed + verified)[:FINAL_VERIFIED_MAX]
        verified_ports = {parse_host_port(link) for link in ordered}
        extras = [link for link in alive_links if parse_host_port(link) not in verified_ports][:EXTRA_UNVERIFIED]
        final = ordered + extras
    else:
        final = alive_links[:FALLBACK_MAX]

    final = final[:MAX_LINKS]

    header = "#profile-title: %s\n#profile-update-interval: %d\n\n" % (PROFILE_TITLE, UPDATE_INTERVAL_HOURS)
    plain = "\n".join(final)
    OUT_PLAIN.write_text(header + plain + "\n", encoding="utf-8")
    OUT_B64.write_text(base64.b64encode(plain.encode("utf-8")).decode("ascii"), encoding="utf-8")

    report_lines = [
        "updated_utc: %s" % datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "method: %s" % method,
        "unique_links: %d" % len(unique),
        "after_tcp_check: %d" % len(alive_links),
        "passed_real_test: %d" % len(verified),
        "speed_tested: %d" % len(speed_results),
        "written_to_sub: %d" % len(final),
        "",
    ] + report
    OUT_REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    log("Saved %d links to %s (method: %s)" % (len(final), OUT_PLAIN.name, method))


if __name__ == "__main__":
    main()
