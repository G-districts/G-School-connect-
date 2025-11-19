# =========================
# G-SCHOOLS CONNECT BACKEND
# =========================

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import json, os, time, sqlite3, traceback, uuid, re
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict

# NEW: DNS + threading imports
import socketserver, socket, threading
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, RCODE

# ---------------------------
# Flask App Initialization
# ---------------------------
app = Flask(__name__, static_url_path="/static", static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")
CORS(app, resources={r"/api/*": {"origins": "*"}})

def _ice_servers():
    # Always include Google STUN
    servers = [{"urls": ["stun:stun.l.google.com:19302"]}]
    # Optional TURN from env
    turn_url = os.environ.get("TURN_URL")
    turn_user = os.environ.get("TURN_USER")
    turn_pass = os.environ.get("TURN_PASS")
    if turn_url and turn_user and turn_pass:
        servers.append({
            "urls": [turn_url],
            "username": turn_user,
            "credential": turn_pass
        })
    return servers


ROOT = os.path.dirname(__file__)
DATA_PATH = os.path.join(ROOT, "data.json")
DB_PATH = os.path.join(ROOT, "gschool.db")
SCENES_PATH = os.path.join(ROOT, "scenes.json")


# =========================
# Helpers: Data & Database
# =========================

def db():
    """Open sqlite connection (row factory stays default to keep light)."""
    con = sqlite3.connect(DB_PATH)
    return con

def _init_db():
    """Create tables if missing; repair structure when possible."""
    con = db()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            k TEXT PRIMARY KEY,
            v TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT,
            role TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT,
            user_id TEXT,
            role TEXT,
            text TEXT,
            ts INTEGER
        );
    """)
    con.commit()
    con.close()

_init_db()

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

def _coerce_to_dict(obj):
    """If file accidentally became a list or invalid type, coerce to default dict."""
    if isinstance(obj, dict):
        return obj
    # Attempt to stitch a list of dict fragments
    if isinstance(obj, list):
        d = _safe_default_data()
        for item in obj:
            if isinstance(item, dict):
                d.update(item)
        return d
    return _safe_default_data()

def load_data():
    """Load JSON with self-repair for common corruption patterns."""
    if not os.path.exists(DATA_PATH):
        d = _safe_default_data()
        save_data(d)
        return d
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
            return ensure_keys(_coerce_to_dict(obj))
    except json.JSONDecodeError as e:
        # Try simple auto-repair: merge stray blocks like "} {"
        try:
            text = open(DATA_PATH, "r", encoding="utf-8").read().strip()
            # Fix common '}{' issues
            text = re.sub(r"}\s*{", "},{", text)
            if not text.startswith("["):
                text = "[" + text
            if not text.endswith("]"):
                text = text + "]"
            arr = json.loads(text)
            obj = _coerce_to_dict(arr)
            save_data(obj)
            return ensure_keys(obj)
        except Exception:
            print("[FATAL] data.json unrecoverable; starting fresh:", e)
            obj = _safe_default_data()
            save_data(obj)
            return obj
    except Exception as e:
        print("[WARN] load_data failed; using defaults:", e)
        return ensure_keys(_safe_default_data())

def save_data(d):
    d = ensure_keys(_coerce_to_dict(d))
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def get_setting(key, default=None):
    con = db(); cur = con.cursor()
    cur.execute("SELECT v FROM settings WHERE k=?", (key,))
    row = cur.fetchone()
    con.close()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except Exception:
        return row[0]

def set_setting(key, value):
    con = db(); cur = con.cursor()
    cur.execute("REPLACE INTO settings (k, v) VALUES (?,?)", (key, json.dumps(value)))
    con.commit(); con.close()

def current_user():
    return session.get("user")

def ensure_keys(d):
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
    # also carry feature flags
    d.setdefault("extension_enabled", True)
    return d

def log_action(entry):
    try:
        d = ensure_keys(load_data())
        log = d.setdefault("audit", [])
        entry = dict(entry or {})
        entry["ts"] = int(time.time())
        log.append(entry)
        d["audit"] = log[-500:]
        save_data(d)
    except Exception:
        pass


# =========================
# Guest handling helper
# =========================
_GUEST_TOKENS = ("guest", "anon", "anonymous", "trial", "temp")

def _is_guest_identity(email: str, name: str) -> bool:
    """Heuristic: treat empty email or names/emails containing guest-like tokens as guest."""
    e = (email or "").strip().lower()
    n = (name or "").strip().lower()
    if not e:
        return True
    if any(t in e for t in _GUEST_TOKENS):
        return True
    if any(t in n for t in _GUEST_TOKENS):
        return True
    return False


# =========================
# Scenes Helpers
# =========================
def _load_scenes():
    try:
        with open(SCENES_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception:
        obj = {"allowed": [], "blocked": [], "current": None}
    obj.setdefault("allowed", [])
    obj.setdefault("blocked", [])
    obj.setdefault("current", None)
    return obj

def _save_scenes(obj):
    obj = obj or {}
    obj.setdefault("allowed", [])
    obj.setdefault("blocked", [])
    obj.setdefault("current", None)
    with open(SCENES_PATH, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


# =========================
# Shared Policy Helpers (HTTP + DNS)
# =========================

def get_policy_snapshot():
    """
    Return the effective allowlist, teacher_blocks, categories, and default block page
    from data.json, using the snapshot that /api/policy maintains when possible.
    """
    d = ensure_keys(load_data())

    # Prefer the snapshot stored by /api/policy
    policy = d.get("policy") or {}
    allowlist = list(policy.get("allowlist", []))
    teacher_blocks = list(policy.get("teacher_blocks", []))

    # Fallback to class config if no snapshot yet
    if not allowlist and not teacher_blocks:
        cls = d["classes"].get("period1", {})
        allowlist = list(cls.get("allowlist", []))
        teacher_blocks = list(cls.get("teacher_blocks", []))

    categories = d.get("categories", {}) or {}

    # Global default block page (used when no category-specific override)
    default_block_page = d.get("settings", {}).get(
        "blocked_redirect",
        "https://blocked.gdistrict.org/Gschool%20block"
    )

    return allowlist, teacher_blocks, categories, default_block_page


def _normalize_pattern_to_domain(pattern: str) -> str:
    """
    Take a Chrome-style or URL pattern and extract a bare domain.
      '*://*.example.com/*' -> 'example.com'
      'https://youtube.com/' -> 'youtube.com'
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


def match_block_category(domain: str):
    """
    Given a domain, decide if it's blocked and, if so, which category
    (if any) and which block page URL should apply.

    Returns:
        (blocked: bool, block_page: str | None, category_name: str | None)
    """
    if not domain:
        return False, None, None

    domain = domain.lower().rstrip(".")
    allowlist, teacher_blocks, categories, default_block_page = get_policy_snapshot()

    # 1) Check teacher_blocks (global override)
    for patt in (teacher_blocks or []):
        ddom = _normalize_pattern_to_domain(patt)
        if not ddom:
            continue
        if domain == ddom or domain.endswith("." + ddom):
            return True, default_block_page, None

    # 2) Check categories' URL patterns (with per-category blockPage override)
    for cat_name, cat in (categories or {}).items():
        cat_block_page = (cat.get("blockPage") or "").strip() or default_block_page
        for patt in (cat.get("urls") or []):
            ddom = _normalize_pattern_to_domain(patt)
            if not ddom:
                continue
            if domain == ddom or domain.endswith("." + ddom):
                return True, cat_block_page, cat_name

    # 3) Optional extra keyword rules (similar to /api/offtask/check)
    bad_kw = ("coolmath", "roblox", "twitch", "steam", "epicgames")
    if any(k in domain for k in bad_kw):
        return True, default_block_page, None

    return False, None, None


def is_blocked_domain(domain: str) -> bool:
    """
    Lightweight helper used by both DNS and HTTP logic.
    """
    blocked, _, _ = match_block_category(domain)
    return blocked


# =========================
# Pages
# =========================
@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login_page"))
    return redirect(url_for("teacher_page" if u["role"] != "admin" else "admin_page"))

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/admin")
def admin_page():
    u = current_user()
    if not u or u["role"] != "admin":
        return redirect(url_for("login_page"))
    return render_template("admin.html", data=load_data(), user=u)

@app.route("/teacher")
def teacher_page():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return redirect(url_for("login_page"))
    return render_template("teacher.html", data=load_data(), user=u)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login_page"))


# =========================
# Teacher Presentation (WebRTC signaling via REST polling)
# =========================

PRESENT = defaultdict(lambda: {
    "offers": {},
    "answers": {},
    "cand_v": defaultdict(list),
    "cand_t": defaultdict(list),
    "updated": int(time.time()),
    "active": False
})

def _clean_room(room):
    r = PRESENT.get(room)
    if not r:
        return
    now = int(time.time())
    r["updated"] = now

@app.route("/teacher/present")
def teacher_present_page():
    u = session.get("user")
    if not u:
        return redirect(url_for("login_page"))
    # room id based on teacher email (stable across session)
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', (u.get("email") or "classroom").split("@")[0])
    return render_template(
        "teacher_present.html",
        data=load_data(),
        ice_servers=_ice_servers(),
        user=u,
        room=room,
    )

@app.route("/present/<room>")
def student_present_view(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    return render_template("present.html", room=room, ice_servers=_ice_servers())

@app.route("/api/present/<room>/start", methods=["POST"])
def api_present_start(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    PRESENT[room]["active"] = True
    PRESENT[room]["updated"] = int(time.time())
    return jsonify({"ok": True, "room": room})

@app.route("/api/present/<room>/end", methods=["POST"])
def api_present_end(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    PRESENT[room] = {
        "offers": {},
        "answers": {},
        "cand_v": defaultdict(list),
        "cand_t": defaultdict(list),
        "updated": int(time.time()),
        "active": False
    }
    return jsonify({"ok": True})

@app.route("/api/present/<room>/status", methods=["GET"])
def api_present_status(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    r = PRESENT.get(room) or {}
    return jsonify({"ok": True, "active": bool(r.get("active"))})

# Viewer posts offer and polls for answer
@app.route("/api/present/<room>/viewer/offer", methods=["POST"])
def api_present_viewer_offer(room):
    body = request.json or {}
    sdp = body.get("sdp")
    client_id = body.get("client_id") or str(uuid.uuid4())
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    r = PRESENT[room]
    r["offers"][client_id] = sdp
    r["updated"] = int(time.time())
    return jsonify({"ok": True, "client_id": client_id})

@app.route("/api/present/<room>/offers", methods=["GET"])
def api_present_offers(room):
    # Teacher polls for pending offers
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    offers = PRESENT[room]["offers"]
    return jsonify({"ok": True, "offers": offers})

@app.route("/api/present/<room>/answer/<client_id>", methods=["POST", "GET"])
def api_present_answer(room, client_id):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    client_id = re.sub(r'[^a-zA-Z0-9_-]+', '', client_id)
    r = PRESENT[room]
    if request.method == "POST":
        body = request.json or {}
        sdp = body.get("sdp")
        r["answers"][client_id] = sdp
        # once answered, remove offer (optional)
        if client_id in r["offers"]:
            del r["offers"][client_id]
        r["updated"] = int(time.time())
        return jsonify({"ok": True})
    else:
        ans = r["answers"].get(client_id)
        return jsonify({"ok": True, "answer": ans})

# ICE candidates (trickle)
@app.route("/api/present/<room>/candidate/<side>/<client_id>", methods=["POST", "GET"])
def api_present_candidate(room, side, client_id):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    client_id = re.sub(r'[^a-zA-Z0-9_-]+', '', client_id)
    side = "viewer" if side.lower().startswith("v") else "teacher"
    r = PRESENT[room]
    bucket_from = r["cand_v"] if side == "viewer" else r["cand_t"]
    bucket_to = r["cand_t"] if side == "viewer" else r["cand_v"]
    if request.method == "POST":
        body = request.json or {}
        cands = body.get("candidates") or []
        if cands:
            bucket_from[client_id].extend(cands)
        r["updated"] = int(time.time())
        return jsonify({"ok": True})
    else:
        # GET fetch and clear incoming candidates for this side
        cands = bucket_to.get(client_id, [])
        bucket_to[client_id] = []
        return jsonify({"ok": True, "candidates": cands})

@app.route("/api/present/<room>/diag", methods=["GET"])
def api_present_diag(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    r = PRESENT.get(room) or {"offers": {}, "answers": {}, "cand_v": {}, "cand_t": {}, "active": False}
    return jsonify({
        "ok": True,
        "active": bool(r.get("active")),
        "offers": len(r.get("offers", {})),
        "answers": len(r.get("answers", {})),
        "cand_v": {k: len(v) for k, v in (r.get("cand_v") or {}).items()},
        "cand_t": {k: len(v) for k, v in (r.get("cand_t") or {}).items()},
    })


# =========================
# Auth
# =========================
@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.json or request.form
    email = (body.get("email") or "").strip().lower()
    pw = body.get("password") or ""
    con = db(); cur = con.cursor()
    cur.execute("SELECT email,role FROM users WHERE email=? AND password=?", (email, pw))
    row = cur.fetchone()
    con.close()
    if row:
        session["user"] = {"email": row[0], "role": row[1]}
        return jsonify({"ok": True, "role": row[1]})
    return jsonify({"ok": False, "error": "Invalid credentials"}), 401


# =========================
# Core Data & Settings
# =========================
@app.route("/api/data")
def api_data():
    """Compatibility wrapper used by teacher.html's loadData()."""
    d = ensure_keys(load_data())
    cls = d["classes"].get("period1", {})
    return jsonify({
        "settings": {
            "chat_enabled": bool(d.get("settings", {}).get("chat_enabled", True)),
            "youtube_mode": get_setting("youtube_mode", "normal"),
        },
        "lists": {
            "teacher_blocks": get_setting("teacher_blocks", []),
            "teacher_allow": get_setting("teacher_allow", []),
        },
        # added for teacher.html compatibility
        "classes": {
            "period1": {
                "name": cls.get("name", "Period 1"),
                "active": bool(cls.get("active", True)),
                "focus_mode": bool(cls.get("focus_mode", False)),
                "paused": bool(cls.get("paused", False)),
                "allowlist": list(cls.get("allowlist", [])),
                "teacher_blocks": list(cls.get("teacher_blocks", [])),
                "students": list(cls.get("students", [])),
            }
        }
    })

@app.route("/api/settings", methods=["POST"])
def api_settings():
    u = current_user()
    if not u or u["role"] != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    b = request.json or {}
    if "blocked_redirect" in b:
        d["settings"]["blocked_redirect"] = b["blocked_redirect"]
    if "chat_enabled" in b:
        d["settings"]["chat_enabled"] = bool(b["chat_enabled"])
        set_setting("chat_enabled", bool(b["chat_enabled"]))
    if "passcode" in b and b["passcode"]:
        d["settings"]["passcode"] = b["passcode"]
    save_data(d)
    return jsonify({"ok": True, "settings": d["settings"]})

@app.route("/api/categories", methods=["POST"])
def api_categories():
    u = current_user()
    if not u or u["role"] != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    d = ensure_keys(load_data())
    b = request.json or {}
    name = b.get("name")
    urls = b.get("urls", [])
    bp = b.get("blockPage", "")
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400

    d["categories"][name] = {"urls": urls, "blockPage": bp}

    # Policy changed → force refresh for all extensions
    d.setdefault("pending_commands", {}).setdefault("*", []).append({
        "type": "policy_refresh"
    })

    save_data(d)
    log_action({"event": "categories_update", "name": name})
    return jsonify({"ok": True})

@app.route("/api/categories/delete", methods=["POST"])
def api_categories_delete():
    u = current_user()
    if not u or u["role"] != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403

    d = ensure_keys(load_data())
    name = (request.json or {}).get("name")
    if name in d["categories"]:
        del d["categories"][name]

        # Policy changed → force refresh
        d.setdefault("pending_commands", {}).setdefault("*", []).append({
            "type": "policy_refresh"
        })

        save_data(d)
        log_action({"event": "categories_delete", "name": name})
    return jsonify({"ok": True})


# =========================
# Class / Teacher Controls
# =========================
@app.route("/api/announce", methods=["POST"])
def api_announce():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    d = ensure_keys(load_data())
    body = request.json or {}

    msg = (
        (body.get("message") or "").strip()
        or (body.get("text") or "").strip()
        or (body.get("announcement") or "").strip()
    )

    d["announcements"] = msg

    # Tell all extensions to re-fetch /api/policy so they see the new announcement
    d.setdefault("pending_commands", {}).setdefault("*", []).append({
        "type": "policy_refresh"
    })

    save_data(d)
    log_action({"event": "announce", "message": msg})
    return jsonify({"ok": True})

@app.route("/api/class/set", methods=["GET", "POST"])
def api_class_set():
    d = ensure_keys(load_data())

    if request.method == "GET":
        cls = d["classes"].get("period1", {})
        return jsonify({"class": cls, "settings": d["settings"]})

    body = request.json or {}
    cls = d["classes"].get("period1", {})
    prev_active = bool(cls.get("active", True))

    if "teacher_blocks" in body:
        set_setting("teacher_blocks", body["teacher_blocks"])
        cls["teacher_blocks"] = list(body["teacher_blocks"])
    else:
        cls.setdefault("teacher_blocks", [])

    if "allowlist" in body:
        set_setting("teacher_allow", body["allowlist"])
        cls["allowlist"] = list(body["allowlist"])
    else:
        cls.setdefault("allowlist", [])

    if "chat_enabled" in body:
        set_setting("chat_enabled", body["chat_enabled"])
        d["settings"]["chat_enabled"] = bool(body["chat_enabled"])



