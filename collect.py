# -*- coding: utf-8 -*-
"""
collect.py
Collects free proxy configs from PUBLIC Telegram channel web pages
(https://t.me/s/<channel>) and writes a subscription file.

Outputs (next to this script):
    sub.txt      plain links, with Hiddify header lines (profile-title, update interval)
    sub_b64.txt  the same links, base64 encoded (fallback for other clients)

Notes:
- Only links from the last MAX_AGE_HOURS hours are kept (newest first).
- If REMOVE_DEAD is True, servers whose TCP port does not answer from the
  machine running this script are dropped. This only removes servers that
  are dead for everybody; it can NOT know what works inside Iran.
- Needs only the Python standard library.
"""

import base64
import datetime
import html
import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ----------------------------- SETTINGS -----------------------------

BASE_DIR = Path(__file__).resolve().parent
CHANNELS_FILE = BASE_DIR / "channels.txt"
OUT_PLAIN = BASE_DIR / "sub.txt"
OUT_B64 = BASE_DIR / "sub_b64.txt"

PROFILE_TITLE = "Daily Configs"   # name shown in Hiddify
UPDATE_INTERVAL_HOURS = 1         # how often Hiddify re-downloads the file

MAX_AGE_HOURS = 48                # ignore posts older than this
PAGES_PER_CHANNEL = 5             # how many pages (about 20 posts each) to read per channel
MAX_LINKS = 400                   # keep at most this many links (newest first)

REMOVE_DEAD = True                # drop servers whose port does not answer
TCP_TIMEOUT = 4.0
MAX_WORKERS = 100

REQUEST_DELAY = 1.0               # seconds between page requests
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


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="ignore")


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


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    channels = read_channels()
    if not channels:
        log("channels.txt is empty. Put one channel username per line, then run again.")
        sys.exit(1)

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=MAX_AGE_HOURS)

    collected = []
    for channel in channels:
        items = collect_channel(channel, cutoff)
        log("%s: %d links" % (channel, len(items)))
        collected.extend(items)
        time.sleep(REQUEST_DELAY)

    collected.sort(key=lambda item: item[0], reverse=True)

    unique = []
    seen = set()
    for _, link in collected:
        key = link.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    log("Total unique links: %d" % len(unique))

    if not unique:
        log("Nothing collected. Keeping the previous files untouched.")
        return

    if REMOVE_DEAD:
        checks = []
        keep_without_test = set()
        for link in unique:
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

        before_count = len(unique)
        unique = [link for link in unique if link in alive]
        log("After removing dead servers: %d of %d links" % (len(unique), before_count))

        if not unique:
            log("Every server looked dead. Keeping the previous files untouched.")
            return

    unique = unique[:MAX_LINKS]

    header = "#profile-title: %s\n#profile-update-interval: %d\n\n" % (PROFILE_TITLE, UPDATE_INTERVAL_HOURS)
    plain = "\n".join(unique)
    OUT_PLAIN.write_text(header + plain + "\n", encoding="utf-8")
    OUT_B64.write_text(base64.b64encode(plain.encode("utf-8")).decode("ascii"), encoding="utf-8")
    log("Saved %d links to %s" % (len(unique), OUT_PLAIN.name))


if __name__ == "__main__":
    main()
