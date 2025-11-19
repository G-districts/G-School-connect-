#!/usr/bin/env python3
"""
G-Schools DNS server

- Reads data.json from the same directory as app.py
- Uses categories + teacher_blocks to decide which domains are blocked
- For blocked domains: returns A record pointing to BLOCK_IP
- For allowed domains: forwards query to an upstream DNS (e.g. 1.1.1.1)
- Listens on 0.0.0.0 so any client IP can use it
"""

import os
import json
import socket
import socketserver
import threading
import re
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, RCODE

# ---------------------------
# Paths
# ---------------------------

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(ROOT, "data.json")


# ---------------------------
# Data & Policy Helpers
# ---------------------------

def _safe_default_data():
    return {
        "settings": {"chat_enabled": False},
        "classes": {
            "period1": {
                "name": "Period 1",
                "active": True,
                "focus_mode": False,
                "paused": False,
                "allowlist": [],
                "teacher_blocks": [],
                "students": []
            }
        },
        "categories": {},
        "pending_commands": {},
        "pending_per_student": {},
        "presence": {},
        "history": {},
        "screenshots": {},
        "dm": {},
        "alerts": [],
        "audit": []
    }


def ensure_keys(d):
    d = d or {}
    d.setdefault("settings", {}).setdefault("chat_enabled", False)
    d.setdefault("classes", {}).setdefault("period1", {
        "name": "Period 1",
        "active": True,
        "focus_mode": False,
        "paused": False,
        "allowlist": [],
        "teacher_blocks": [],
        "students": []
    })
    d.setdefault("categories", {})
    d.setdefault("pending_commands", {})
    d.setdefault("pending_per_student", {})
    d.setdefault("presence", {})
    d.setdefault("history", {})
    d.setdefault("screenshots", {})
    d.setdefault("alerts", [])
    d.setdefault("dm", {})
    d.setdefault("audit", [])
    d.setdefault("extension_enabled", True)
    return d


def load_data():
    if not os.path.exists(DATA_PATH):
        return ensure_keys(_safe_default_data())
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
        # If somehow it became a list, coerce into dict
        if not isinstance(obj, dict):
            if isinstance(obj, list):
                base = _safe_default_data()
                for item in obj:
                    if isinstance(item, dict):
                        base.update(item)
                obj = base
            else:
                obj = _safe_default_data()
        return ensure_keys(obj)
    except Exception as e:
        print(f"[DNS] Failed to load data.json, using defaults: {e}")
        return ensure_keys(_safe_default_data())


def _normalize_pattern_to_domain(pattern: str) -> str:
    """
    Convert URL/pattern into a bare domain string.

    Examples:
      '*://*.example.com/*' -> 'example.com'
      'https://youtube.com/' -> 'youtube.com'
      'example.org' -> 'example.org'
    """
    s = (pattern or "").strip()
    if not s:
        return ""

    # Chrome-style '*://*.example.com/*'
    m = re.match(r"\*\:\/\/\*\.(.+?)\/\*", s)
    if m:
        return m.group(1).lower()

    # Strip protocol and wildcards
    s = re.sub(r"^\*\:\/\/", "", s)          # remove leading *://
    s = re.sub(r"^https?:\/\/", "", s)       # remove http(s)://
    s = s.strip("/*")                        # trim wildcards and slashes
    return s.lower()


def get_policy_snapshot():
    """
    Return (allowlist, teacher_blocks, categories, default_block_page)
    based on data.json contents.

    Prefers d['policy'] if set by the Flask app (/api/policy).
    """
    d = load_data()

    policy = d.get("policy") or {}
    allowlist = list(policy.get("allowlist", []))
    teacher_blocks = list(policy.get("teacher_blocks", []))

    # Fallback to class-level policy if snapshot missing
    if not allowlist and not teacher_blocks:
        cls = d["classes"].get("period1", {})
        allowlist = list(cls.get("allowlist", []))
        teacher_blocks = list(cls.get("teacher_blocks", []))

    categories = d.get("categories", {}) or {}

    default_block_page = d.get("settings", {}).get(
        "blocked_redirect",
        "https://blocked.gdistrict.org/Gschool%20block"
    )

    return allowlist, teacher_blocks, categories, default_block_page


def match_block_category(domain: str):
    """
    Decide if a domain is blocked based on categories + teacher_blocks.

    Returns:
        (blocked: bool, block_page: str | None, category_name: str | None)
    """
    if not domain:
        return False, None, None

    domain = domain.lower().rstrip(".")

    allowlist, teacher_blocks, categories, default_block_page = get_policy_snapshot()

    # 1) Teacher global blocks
    for patt in (teacher_blocks or []):
        ddom = _normalize_pattern_to_domain(patt)
        if not ddom:
            continue
        if domain == ddom or domain.endswith("." + ddom):
            return True, default_block_page, None

    # 2) Categories (per-category blockPage)
    for cat_name, cat in (categories or {}).items():
        cat_block_page = (cat.get("blockPage") or "").strip() or default_block_page
        for patt in (cat.get("urls") or []):
            ddom = _normalize_pattern_to_domain(patt)
            if not ddom:
                continue
            if domain == ddom or domain.endswith("." + ddom):
                return True, cat_block_page, cat_name

    # 3) Extra keyword-based rules (like off-task check)
    bad_kw = ("coolmath", "roblox", "twitch", "steam", "epicgames")
    if any(k in domain for k in bad_kw):
        return True, default_block_page, None

    return False, None, None


# ---------------------------
# DNS Server
# ---------------------------

def _guess_host_ip():
    """
    Try to guess the primary IP address of this machine (for BLOCK_IP default).
    If it fails, fall back to 127.0.0.1.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable; just used to get the local interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


UPSTREAM_DNS = os.environ.get("UPSTREAM_DNS", "1.1.1.1")          # Cloudflare by default
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "53"))
BLOCK_IP = os.environ.get("BLOCK_IP", _guess_host_ip())           # IP for blocked domains
DNS_HOST = os.environ.get("DNS_HOST", "0.0.0.0")                  # Listen address
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))                  # Listen port


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip, client_port = self.client_address

        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            print(f"[DNS] Failed to parse request from {client_ip}: {e}")
            return

        q = request.questions[0] if request.questions else None
        if not q:
            return

        qname = str(q.qname)
        qtype = QTYPE.get(q.qtype, "A")
        domain = qname.rstrip(".").lower()

        print(f"[DNS] Query from {client_ip} for {domain} ({qtype})")

        # Only filter A queries; forward others as-is
        if qtype == "A":
            blocked, block_page, category = match_block_category(domain)
        else:
            blocked, block_page, category = (False, None, None)

        if blocked:
            # DNS only knows to send them to BLOCK_IP; HTTP decides exact block page.
            print(f"[DNS] Blocked {domain} -> {BLOCK_IP} (category={category})")
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                q=request.q
            )
            try:
                reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(BLOCK_IP)))
            except Exception as e:
                print(f"[DNS] Error building blocked reply: {e}")
                reply.header.rcode = RCODE.SERVFAIL
            sock.sendto(reply.pack(), self.client_address)
            return

        # Not blocked: forward to upstream resolver
        try:
            upstream_addr = (UPSTREAM_DNS, UPSTREAM_PORT)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3.0)
                s.sendto(data, upstream_addr)
                resp, _ = s.recvfrom(65535)
            sock.sendto(resp, self.client_address)
        except Exception as e:
            print(f"[DNS] Upstream resolution failed for {domain}: {e}")
            # Fallback: SERVFAIL
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.SERVFAIL), q=request.q)
            sock.sendto(reply.pack(), self.client_address)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


def run_dns_server(host: str = None, port: int = None):
    """
    Start the DNS server (blocking call).

    host="0.0.0.0" means it will accept queries from ANY client IP.
    """
    host = host or DNS_HOST
    port = port or DNS_PORT
    server = ThreadedUDPServer((host, port), DNSUDPHandler)
    print(f"[DNS] G-Schools DNS server listening on {host}:{port}, BLOCK_IP={BLOCK_IP}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DNS] Shutting down...")
    finally:
        server.shutdown()
        server.server_close()


def start_dns_in_background(host: str = None, port: int = None):
    """
    Start DNS server in a background thread.

    Call this from app.py so DNS comes up whenever app.py is run.
    """
    host = host or DNS_HOST
    port = port or DNS_PORT

    def _runner():
        run_dns_server(host, port)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    print(f"[DNS] Background DNS thread started on {host}:{port}")
    return t


if __name__ == "__main__":
    # Standalone mode: `python dns_server.py`
    run_dns_server()
