# =========================
# G-SCHOOLS CONNECT BACKEND
# =========================

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import json, os, time, sqlite3, traceback, uuid, re
from urllib.parse import urlparse

# ---------------------------
# Flask App Initialization
# ---------------------------
app = Flask(__name__, static_url_path="/static", static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")
CORS(app, resources={r"/api/*": {"origins": "*"}})

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

from datetime import datetime
from collections import defaultdict

# In-memory session store: {room: {offers:{client_id: sdp}, answers:{client_id:sdp}, cand_v:{client_id:[cands]}, cand_t:{client_id:[cands]}, updated:int, active:bool}}
PRESENT = defaultdict(lambda: {"offers": {}, "answers": {}, "cand_v": defaultdict(list), "cand_t": defaultdict(list), "updated": int(time.time()), "active": False})

def _clean_room(room):
    r = PRESENT.get(room)
    if not r: return
    # drop stale viewers (> 10 minutes inactivity)
    now = int(time.time())
    for cid in list(r["offers"].keys()):
        # if no answer & offer older than 10 min, drop
        pass
    r["updated"] = now

@app.route("/teacher/present")
def teacher_present_page():
    u = session.get("user")
    if not u:
        return redirect(url_for("login_page"))
    # room id based on teacher email (stable across session)
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', (u.get("email") or "classroom").split("@")[0])
    return render_template("teacher_present.html", data=load_data(), user=u, room=room)

@app.route("/present/<room>")
def student_present_view(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    return render_template("present.html", room=room)

@app.route("/api/present/<room>/start", methods=["POST"])
def api_present_start(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    PRESENT[room]["active"] = True
    PRESENT[room]["updated"] = int(time.time())
    return jsonify({"ok": True, "room": room})

@app.route("/api/present/<room>/end", methods=["POST"])
def api_present_end(room):
    room = re.sub(r'[^a-zA-Z0-9_-]+', '', room)
    PRESENT[room] = {"offers": {}, "answers": {}, "cand_v": defaultdict(list), "cand_t": defaultdict(list), "updated": int(time.time()), "active": False}
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
    client_id = re.sub(r'[^a-zA-Z0-9_-]+','', client_id)
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
    client_id = re.sub(r'[^a-zA-Z0-9_-]+','', client_id)
    side = "viewer" if side.lower().startswith("v") else "teacher"
    r = PRESENT[room]
    bucket_from = r["cand_v"] if side == "viewer" else r["cand_t"]
    bucket_to   = r["cand_t"] if side == "viewer" else r["cand_v"]
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
    return jsonify({
        "settings": {
            "chat_enabled": bool(get_setting("chat_enabled", True)),
            "youtube_mode": get_setting("youtube_mode", "normal"),
        },
        "lists": {
            "teacher_blocks": get_setting("teacher_blocks", []),
            "teacher_allow": get_setting("teacher_allow", []),
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
    save_data(d)
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
        save_data(d)
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
    d["announcements"] = (request.json or {}).get("message", "")
    save_data(d)
    log_action({"event": "announce"})
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

    if "active" in body:
        cls["active"] = bool(body["active"])
    if "passcode" in body and body["passcode"]:
        d["settings"]["passcode"] = body["passcode"]

    d["classes"]["period1"] = cls

    if bool(cls.get("active", True)) and not prev_active:
        d.setdefault("pending_commands", {}).setdefault("*", []).append({
            "type": "notify",
            "title": "Class session is active",
            "message": "Please join and stay until dismissed."
        })

    save_data(d)
    log_action({"event": "class_set", "active": cls.get("active", True)})
    return jsonify({"ok": True, "class": cls, "settings": d["settings"]})

@app.route("/api/class/toggle", methods=["POST"])
def api_class_toggle():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    d = ensure_keys(load_data())
    b = request.json or {}
    cid = b.get("class_id", "period1")
    key = b.get("key")
    val = bool(b.get("value"))

    if cid in d["classes"] and key in ("focus_mode", "paused"):
        d["classes"][cid][key] = val
        save_data(d)
        log_action({"event": "class_toggle", "key": key, "value": val})
        return jsonify({"ok": True, "class": d["classes"][cid]})

    return jsonify({"ok": False, "error": "invalid"}), 400


# =========================
# Commands
# =========================
@app.route("/api/command", methods=["POST"])
def api_command():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    b = request.json or {}
    target = b.get("student") or "*"
    cmd = b.get("command")
    if not cmd or "type" not in cmd:
        return jsonify({"ok": False, "error": "invalid"}), 400
    d.setdefault("pending_commands", {}).setdefault(target, []).append(cmd)
    save_data(d)
    log_action({"event": "command", "target": target, "type": cmd.get("type")})
    return jsonify({"ok": True})

@app.route("/api/commands/<student>", methods=["GET", "POST"])
def api_commands(student):
    d = ensure_keys(load_data())

    if request.method == "GET":
        cmds = d["pending_commands"].get(student, []) + d["pending_commands"].get("*", [])
        d["pending_commands"][student] = []
        d["pending_commands"]["*"] = []
        save_data(d)
        return jsonify({"commands": cmds})

    # POST (push from teacher)
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    b = request.json or {}
    if not b.get("type"):
        return jsonify({"ok": False, "error": "missing type"}), 400

    d["pending_commands"].setdefault(student, []).append(b)
    save_data(d)
    log_action({"event": "command_sent", "to": student, "cmd": b.get("type")})
    return jsonify({"ok": True})


# =========================
# Off-task Check (simple)
# =========================
@app.route("/api/offtask/check", methods=["POST"])
def api_offtask_check():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    url = (b.get("url") or "")
    if not student or not url:
        return jsonify({"ok": False}), 400

    d = ensure_keys(load_data())
    # allowlist from policy (scene) if any
    scene_allowed = set()
    for patt in (d.get("policy", {}).get("allowlist") or []):
        m = re.match(r"\*\:\/\/\*\.(.+?)\/\*", patt)
        if m:
            scene_allowed.add(m.group(1).lower())

    host = ""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        pass

    on_task = any(host.endswith(dom) for dom in scene_allowed) if host else False
    bad_kw = ("coolmath", "roblox", "twitch", "steam", "epicgames")
    if any(k in url.lower() for k in bad_kw):
        on_task = False

    v = {"student": student, "url": url, "ts": int(time.time()), "on_task": bool(on_task)}
    d.setdefault("offtask_events", []).append(v)
    d["offtask_events"] = d["offtask_events"][-2000:]
    save_data(d)

    try:
        # If using socketio, you could emit here; safely ignore if not present
        from flask_socketio import SocketIO  # type: ignore
        socketio = SocketIO(message_queue=None)
        socketio.emit("offtask", v, broadcast=True)
    except Exception:
        pass

    return jsonify({"ok": True, "on_task": bool(on_task)})


# =========================
# Presence / Heartbeat
# =========================
@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    """Student heartbeat – updates presence, logs timeline, screenshots, and returns extension state."""
    b = request.json or {}
    student = (b.get("student") or "").strip()
    display_name = b.get("student_name", "")

    # Global kill switch (safe if file type changed)
    data_global = ensure_keys(load_data())
    extension_enabled_global = bool(data_global.get("extension_enabled", True))

    # Hard-disable guest/anonymous identities – do NOT log or persist anything
    if _is_guest_identity(student, display_name):
        return jsonify({
            "ok": True,
            "server_time": int(time.time()),
            "extension_enabled": False  # completely disabled for guests
        })

    d = ensure_keys(load_data())
    d.setdefault("presence", {})

    if student:
        pres = d["presence"].setdefault(student, {})
        pres["last_seen"] = int(time.time())
        pres["student_name"] = display_name
        pres["tab"] = b.get("tab", {}) or {}
        pres["tabs"] = b.get("tabs", []) or []
        # support both camel and snake favicon key names
        if "favIconUrl" in pres.get("tab", {}):
            pass
        elif "favicon" in pres.get("tab", {}):
            pres["tab"]["favIconUrl"] = pres["tab"].get("favicon")

        pres["screenshot"] = b.get("screenshot", "") or ""

        # --- Keep only screenshots for open tabs shown in modal preview ---
        shots = pres.get("tabshots", {})
        for k, v in (b.get("tabshots", {}) or {}).items():
            shots[str(k)] = v
        open_ids = {str(t.get("id")) for t in pres["tabs"] if "id" in t}
        for k in list(shots.keys()):
            if k not in open_ids:
                del shots[k]
        pres["tabshots"] = shots
        d["presence"][student] = pres

        # ---------- Timeline & Screenshot history ----------
        try:
            timeline = d.setdefault("history", {}).setdefault(student, [])
            now = int(time.time())
            cur = pres.get("tab", {}) or {}
            url = (cur.get("url") or "").strip()
            title = (cur.get("title") or "").strip()
            fav = cur.get("favIconUrl")

            should_add = False
            if url:
                if not timeline:
                    should_add = True
                else:
                    last = timeline[-1]
                    if last.get("url") != url or now - int(last.get("ts", 0)) >= 15:
                        should_add = True

            if should_add:
                timeline.append({"ts": now, "title": title, "url": url, "favIconUrl": fav})
                d["history"][student] = timeline[-500:]  # cap

            # Screenshot history: if extension passes `shot_log: [{tabId,dataUrl,title,url}]`
            shot_log = b.get("shot_log") or []
            if shot_log:
                hist = d.setdefault("screenshots", {}).setdefault(student, [])
                for s in shot_log[:10]:
                    hist.append({
                        "ts": now,
                        "tabId": s.get("tabId"),
                        "dataUrl": s.get("dataUrl"),
                        "title": (s.get("title") or ""),
                        "url": (s.get("url") or "")
                    })
                d["screenshots"][student] = hist[-200:]
        except Exception as e:
            print("[WARN] Heartbeat logging error:", e)

    save_data(d)

    return jsonify({
        "ok": True,
        "server_time": int(time.time()),
        # Honor global kill switch but also keep guest lockout enforced above.
        "extension_enabled": bool(extension_enabled_global)
    })

@app.route("/api/presence")
def api_presence():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    return jsonify(load_data().get("presence", {}))


# =========================
# Extension Global Toggle
# =========================
@app.route("/api/extension/toggle", methods=["POST"])
def api_extension_toggle():
    """Toggle all student extensions (remote control by teacher/admin)."""
    user = current_user()
    if not user or user.get("role") not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    body = request.json or {}
    enabled = bool(body.get("enabled", True))

    data = ensure_keys(load_data())
    data["extension_enabled"] = enabled
    save_data(data)

    print(f"[INFO] Extension toggle → {'ENABLED' if enabled else 'DISABLED'} by {user.get('email')}")
    log_action({"event": "extension_toggle", "enabled": enabled, "by": user.get("email")})
    return jsonify({"ok": True, "extension_enabled": enabled})


# =========================
# Policy
# =========================
@app.route("/api/policy", methods=["POST"])
def api_policy():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    d = ensure_keys(load_data())
    cls = d["classes"]["period1"]

    # Base flags
    focus = bool(cls.get("focus_mode", False))
    paused = bool(cls.get("paused", False))

    # Per-student overrides
    ov = d.get("student_overrides", {}).get(student, {}) if student else {}
    focus = bool(ov.get("focus_mode", focus))
    paused = bool(ov.get("paused", paused))

    # deliver any per-student pending commands (one-shot)
    pending = d.get("pending_per_student", {}).get(student, []) if student else []
    if student and student in d.get("pending_per_student", {}):
        d["pending_per_student"].pop(student, None)
        save_data(d)

    # Scene merge logic (no over-blocking)
    store = _load_scenes()
    current = store.get("current") or None

    # Start with class-level lists
    allowlist = list(cls.get("allowlist", []))
    teacher_blocks = list(cls.get("teacher_blocks", []))

    if current:
        scene_obj = None
        for bucket in ("allowed", "blocked"):
            for s in store.get(bucket, []):
                if str(s.get("id")) == str(current.get("id")):
                    scene_obj = s
                    break
            if scene_obj:
                break

        if scene_obj:
            if scene_obj.get("type") == "allowed":
                # allow-only mode (focus true)
                allowlist = list(scene_obj.get("allow", []))
                focus = True
            elif scene_obj.get("type") == "blocked":
                # add extra teacher block patterns
                teacher_blocks = (teacher_blocks or []) + list(scene_obj.get("block", []))

    resp = {
        "blocked_redirect": d.get("settings", {}).get("blocked_redirect", "https://blocked.gdistrict.org/Gschool%20block"),
        "categories": d.get("categories", {}),
        "focus_mode": bool(focus),
        "paused": bool(paused),
        "announcement": d.get("announcements", ""),
        "class": {
            "id": "period1",
            "name": cls.get("name", "Period 1"),
            "active": bool(cls.get("active", True))
        },
        "allowlist": allowlist,
        "teacher_blocks": teacher_blocks,
        "chat_enabled": d.get("settings", {}).get("chat_enabled", False),
        "pending": pending,
        "ts": int(time.time()),
        "scenes": {"current": current}
    }
    return jsonify(resp)


# =========================
# Timeline & Screenshots
# =========================
@app.route("/api/timeline", methods=["GET"])
def api_timeline():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    student = (request.args.get("student") or "").strip()
    limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    since = int(request.args.get("since", 0))
    out = []
    if student:
        out = [e for e in d.get("history", {}).get(student, []) if e.get("ts", 0) >= since]
        out.sort(key=lambda x: x.get("ts", 0))
    else:
        for s, arr in (d.get("history", {}) or {}).items():
            for e in arr:
                if e.get("ts", 0) >= since:
                    out.append(dict(e, student=s))
        out.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return jsonify({"ok": True, "items": out[-limit:]})

@app.route("/api/screenshots", methods=["GET"])
def api_screenshots():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    student = (request.args.get("student") or "").strip()
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    items = []

    if student:
        items = list(d.get("screenshots", {}).get(student, []))
        for it in items:
            it.setdefault("student", student)
    else:
        for s, arr in (d.get("screenshots", {}) or {}).items():
            for e in arr:
                items.append(dict(e, student=s))
        items.sort(key=lambda x: x.get("ts", 0), reverse=True)

    return jsonify({"ok": True, "items": items[-limit:]})


# =========================
# Alerts (Off-task)
# =========================
@app.route("/api/alerts", methods=["GET", "POST"])
def api_alerts():
    d = ensure_keys(load_data())
    if request.method == "POST":
        b = request.json or {}
        u = current_user()
        student = (b.get("student") or (u["email"] if (u and u.get("role") == "student") else "")).strip()
        if not student:
            return jsonify({"ok": False, "error": "student required"}), 400
        item = {
            "ts": int(time.time()),
            "student": student,
            "kind": b.get("kind", "off_task"),
            "score": float(b.get("score") or 0.0),
            "title": (b.get("title") or ""),
            "url": (b.get("url") or ""),
            "note": (b.get("note") or "")
        }
        d.setdefault("alerts", []).append(item)
        d["alerts"] = d["alerts"][-500:]
        save_data(d)
        log_action({"event": "alert", "student": student, "kind": item["kind"], "score": item["score"]})
        return jsonify({"ok": True})

    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    return jsonify({"ok": True, "items": d.get("alerts", [])[-200:]})


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    b = request.json or {}
    student = (b.get("student") or "").strip()
    d = ensure_keys(load_data())
    if student:
        d["alerts"] = [a for a in d.get("alerts", []) if a.get("student") != student]
    else:
        d["alerts"] = []
    save_data(d)
    return jsonify({"ok": True})


# =========================
# Scenes API
# =========================
@app.route("/api/scenes", methods=["GET"])
def api_scenes_list():
    return jsonify(_load_scenes())

@app.route("/api/scenes", methods=["POST"])
def api_scenes_create():
    body = request.json or {}
    name = body.get("name")
    s_type = body.get("type")  # "allowed" or "blocked"
    if not name or s_type not in ("allowed", "blocked"):
        return jsonify({"ok": False, "error": "name and valid type required"}), 400

    scenes = _load_scenes()
    new_scene = {
        "id": str(int(time.time() * 1000)),
        "name": name,
        "type": s_type,
        "allow": body.get("allow", []),
        "block": body.get("block", []),
        "icon": body.get("icon", "blue")
    }
    scenes[s_type].append(new_scene)
    _save_scenes(scenes)

    log_action({"event": "scene_create", "id": new_scene["id"], "name": name})
    return jsonify({"ok": True, "scene": new_scene})

@app.route("/api/scenes/<sid>", methods=["PUT"])
def api_scenes_update(sid):
    body = request.json or {}
    scenes = _load_scenes()
    updated = None
    for bucket in ("allowed", "blocked"):
        for s in scenes.get(bucket, []):
            if s.get("id") == sid:
                s.update(body)
                updated = s
                break
    if not updated:
        return jsonify({"ok": False, "error": "not found"}), 404
    _save_scenes(scenes)
    log_action({"event": "scene_update", "id": sid})
    return jsonify({"ok": True, "scene": updated})

@app.route("/api/scenes/<sid>", methods=["DELETE"])
def api_scenes_delete(sid):
    scenes = _load_scenes()
    for bucket in ("allowed", "blocked"):
        scenes[bucket] = [s for s in scenes.get(bucket, []) if s.get("id") != sid]
    if scenes.get("current", {}).get("id") == sid:
        scenes["current"] = None
    _save_scenes(scenes)
    log_action({"event": "scene_delete", "id": sid})
    return jsonify({"ok": True})

@app.route("/api/scenes/export", methods=["GET"])
def api_scenes_export():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    store = _load_scenes()
    scene_id = request.args.get("id")
    if scene_id:
        for bucket in ("allowed", "blocked"):
            for s in store.get(bucket, []):
                if s.get("id") == scene_id:
                    return jsonify({"ok": True, "scene": s})
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "scenes": store})

@app.route("/api/scenes/import", methods=["POST"])
def api_scenes_import():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    body = request.json or {}
    store = _load_scenes()
    if "scene" in body:
        sc = dict(body["scene"])
        sc["id"] = sc.get("id") or ("scene_" + str(int(time.time() * 1000)))
        if sc.get("type") == "allowed":
            store.setdefault("allowed", []).append(sc)
        else:
            sc["type"] = "blocked"
            store.setdefault("blocked", []).append(sc)
        _save_scenes(store)
        return jsonify({"ok": True, "id": sc["id"]})
    elif "scenes" in body:
        _save_scenes(body["scenes"])
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid payload"}), 400

@app.route("/api/scenes/apply", methods=["POST"])
def api_scenes_apply():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    body = request.json or {}
    sid = body.get("id") or body.get("scene_id")
    disable = bool(body.get("disable", False))

    store = _load_scenes()

    if disable:
        store["current"] = None
        _save_scenes(store)
        log_action({"event": "scene_disabled"})
        return jsonify({"ok": True, "current": None})

    if not sid:
        return jsonify({"ok": False, "error": "scene_id required"}), 400

    found = None
    for bucket in ("allowed", "blocked"):
        for s in store.get(bucket, []):
            if str(s.get("id")) == str(sid):
                found = {"id": s["id"], "name": s.get("name"), "type": s.get("type")}
                break
        if found:
            break

    if not found:
        return jsonify({"ok": False, "error": "scene not found"}), 404

    store["current"] = found
    _save_scenes(store)
    log_action({"event": "scene_applied", "scene": found})

    # Push a refresh command to all students
    d = ensure_keys(load_data())
    d.setdefault("pending_commands", {}).setdefault("*", []).append({"type": "policy_refresh"})
    save_data(d)
    return jsonify({"ok": True, "current": found})

@app.route("/api/scenes/clear", methods=["POST"])
def api_scenes_clear():
    scenes = _load_scenes()
    scenes["current"] = None
    _save_scenes(scenes)
    log_action({"event": "scene_clear"})
    return jsonify({"ok": True})


# =========================
# Direct Messages
# =========================
@app.route("/api/dm/send", methods=["POST"])
def api_dm_send():
    body = request.json or {}
    u = current_user()

    if not u:
        if body.get("from") == "student" and body.get("student"):
            u = {"email": body["student"], "role": "student"}

    if not u:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "empty"}), 400

    if u["role"] == "student":
        room = f"dm:{u['email']}"
        role = "student"; user_id = u["email"]
    elif u["role"] == "teacher":
        student = body.get("student")
        if not student:
            return jsonify({"ok": False, "error": "no student"}), 400
        room = f"dm:{student}"
        role = "teacher"; user_id = u["email"]
    else:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    con = db(); cur = con.cursor()
    cur.execute("INSERT INTO chat_messages(room,user_id,role,text,ts) VALUES(?,?,?,?,?)",
                (room, user_id, role, text, int(time.time())))
    con.commit(); con.close()
    return jsonify({"ok": True})

@app.route("/api/dm/me", methods=["GET"])
def api_dm_me():
    u = current_user()
    student = None

    if u and u["role"] == "student":
        student = u["email"]
    if not student:
        student = request.args.get("student")

    if not student:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    con = db(); cur = con.cursor()
    cur.execute("SELECT user_id,role,text,ts FROM chat_messages WHERE room=? ORDER BY ts ASC", (f"dm:{student}",))
    msgs = [{"from": r[1], "user": r[0], "text": r[2], "ts": r[3]} for r in cur.fetchall()]
    con.close()
    return jsonify(msgs)

@app.route("/api/dm/<student>", methods=["GET"])
def api_dm_get(student):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    msgs = d.get("dm", {}).get(student, [])[-200:]
    return jsonify({"messages": msgs})

@app.route("/api/dm/unread", methods=["GET"])
def api_dm_unread():
    d = ensure_keys(load_data())
    out = {}
    for student, msgs in d.get("dm", {}).items():
        out[student] = sum(1 for m in msgs if m.get("from") == "student" and m.get("unread", True))
    return jsonify(out)

@app.route("/api/dm/mark_read", methods=["POST"])
def api_dm_mark_read():
    body = request.json or {}
    student = body.get("student")
    d = ensure_keys(load_data())
    if student in d.get("dm", {}):
        for m in d["dm"][student]:
            if m.get("from") == "student":
                m["unread"] = False
        save_data(d)
    return jsonify({"ok": True})


# =========================
# Attention Check
# =========================
@app.route("/api/attention_check", methods=["POST"])
def api_attention_check():
    body = request.json or {}
    title = body.get("title", "Are you paying attention?")
    timeout = int(body.get("timeout", 30))

    d = ensure_keys(load_data())
    d["attention_check"] = {"title": title, "timeout": timeout, "ts": int(time.time()), "responses": {}}

    d.setdefault("pending_commands", {}).setdefault("*", []).append({
        "type": "attention_check",
        "title": title,
        "timeout": timeout
    })
    save_data(d)
    log_action({"event": "attention_check_start", "title": title})
    return jsonify({"ok": True})

@app.route("/api/attention_response", methods=["POST"])
def api_attention_response():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    response = b.get("response", "")
    d = ensure_keys(load_data())
    check = d.get("attention_check")
    if not check:
        return jsonify({"ok": False, "error": "no active check"}), 400
    check["responses"][student] = {"response": response, "ts": int(time.time())}
    save_data(d)
    log_action({"event": "attention_response", "student": student, "response": response})
    return jsonify({"ok": True})

@app.route("/api/attention_results")
def api_attention_results():
    d = ensure_keys(load_data())
    return jsonify(d.get("attention_check", {}))


# =========================
# Per-Student Controls
# =========================
@app.route("/api/student/set", methods=["POST"])
def api_student_set():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    b = request.json or {}
    student = (b.get("student") or "").strip()
    if not student:
        return jsonify({"ok": False, "error": "student required"}), 400
    d = ensure_keys(load_data())
    ov = d.setdefault("student_overrides", {}).setdefault(student, {})
    if "focus_mode" in b:
        ov["focus_mode"] = bool(b.get("focus_mode"))
    if "paused" in b:
        ov["paused"] = bool(b.get("paused"))
    save_data(d)
    log_action({"event": "student_set", "student": student, "focus_mode": ov.get("focus_mode"), "paused": ov.get("paused")})
    return jsonify({"ok": True, "overrides": ov})

@app.route("/api/open_tabs", methods=["POST"])
def api_open_tabs_alias():
    b = request.json or {}
    urls = b.get("urls") or []
    student = (b.get("student") or "").strip()
    if not urls:
        return jsonify({"ok": False, "error": "urls required"}), 400

    d = load_data()
    d.setdefault("pending_commands", {})
    if student:
        pend = d.setdefault("pending_per_student", {})
        arr = pend.setdefault(student, [])
        arr.append({"type": "open_tabs", "urls": urls, "ts": int(time.time())})
        arr[:] = arr[-50:]
        log_action({"event": "student_tabs", "student": student, "type": "open_tabs", "count": len(urls)})
    else:
        d["pending_commands"].setdefault("*", []).append({"type": "open_tabs", "urls": urls, "ts": int(time.time())})
        log_action({"event": "class_tabs", "target": "*", "type": "open_tabs", "count": len(urls)})
    save_data(d)
    return jsonify({"ok": True})

@app.route("/api/student/tabs_action", methods=["POST"])
def api_student_tabs_action():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    b = request.json or {}
    student = (b.get("student") or "").strip()
    action = (b.get("action") or "").strip()  # 'restore_tabs' | 'close_tabs'
    if not student or action not in ("restore_tabs", "close_tabs"):
        return jsonify({"ok": False, "error": "student and valid action required"}), 400
    d = ensure_keys(load_data())
    pend = d.setdefault("pending_per_student", {})
    arr = pend.setdefault(student, [])
    arr.append({"type": action, "ts": int(time.time())})
    arr[:] = arr[-50:]
    save_data(d)
    log_action({"event": "student_tabs", "student": student, "type": action})
    return jsonify({"ok": True})


# =========================
# Class Chat
# =========================
@app.route("/api/chat/<class_id>", methods=["GET", "POST"])
def api_chat(class_id):
    d = ensure_keys(load_data())
    d.setdefault("chat", {}).setdefault(class_id, [])
    if request.method == "POST":
        b = request.json or {}
        txt = (b.get("text") or "")[:500]
        sender = b.get("from") or "student"
        if not txt:
            return jsonify({"ok": False, "error": "empty"}), 400
        d["chat"][class_id].append({"from": sender, "text": txt, "ts": int(time.time())})
        d["chat"][class_id] = d["chat"][class_id][-200:]
        save_data(d)
        return jsonify({"ok": True})
    return jsonify({"enabled": d.get("settings", {}).get("chat_enabled", False), "messages": d["chat"][class_id][-100:]})


# =========================
# Raise Hand
# =========================
@app.route("/api/raise_hand", methods=["POST"])
def api_raise_hand():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    note = (b.get("note") or "").strip()
    d = ensure_keys(load_data())
    d.setdefault("raises", [])
    d["raises"].append({"student": student, "note": note, "ts": int(time.time())})
    d["raises"] = d["raises"][-200:]
    save_data(d)
    log_action({"event": "raise_hand", "student": student})
    return jsonify({"ok": True})

@app.route("/api/raise_hand", methods=["GET"])
def get_hands():
    d = ensure_keys(load_data())
    return jsonify({"hands": d.get("raises", [])})

@app.route("/api/raise_hand/clear", methods=["POST"])
def clear_hand():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    d = ensure_keys(load_data())
    lst = d.get("raises", [])
    if student:
        lst = [r for r in lst if r.get("student") != student]
    else:
        lst = []
    d["raises"] = lst
    save_data(d)
    return jsonify({"ok": True, "remaining": len(lst)})


# =========================
# YouTube / Doodle settings
# =========================
@app.route("/api/youtube_rules", methods=["GET", "POST"])
def api_youtube_rules():
    if request.method == "POST":
        body = request.json or {}
        set_setting("yt_block_keywords", body.get("block_keywords", []))
        set_setting("yt_block_channels", body.get("block_channels", []))
        set_setting("yt_allow", body.get("allow", []))
        set_setting("yt_allow_mode", bool(body.get("allow_mode", False)))

        # Broadcast an update command to all present students
        d = ensure_keys(load_data())
        d.setdefault("pending_commands", {}).setdefault("*", []).append({
            "type": "update_youtube_rules",
            "rules": {
                "block_keywords": body.get("block_keywords", []),
                "block_channels": body.get("block_channels", []),
                "allow": body.get("allow", []),
                "allow_mode": bool(body.get("allow_mode", False))
            }
        })
        save_data(d)

        log_action({"event": "youtube_rules_update"})
        return jsonify({"ok": True})

    rules = {
        "block_keywords": get_setting("yt_block_keywords", []),
        "block_channels": get_setting("yt_block_channels", []),
        "allow": get_setting("yt_allow", []),
        "allow_mode": bool(get_setting("yt_allow_mode", False)),
    }
    return jsonify(rules)

@app.route("/api/doodle_block", methods=["GET", "POST"])
def api_doodle_block():
    if request.method == "POST":
        body = request.json or {}
        enabled = bool(body.get("enabled", False))
        set_setting("block_google_doodles", enabled)
        log_action({"event": "doodle_block_update", "enabled": enabled})
        return jsonify({"ok": True, "enabled": enabled})
    return jsonify({"enabled": bool(get_setting("block_google_doodles", False))})


# =========================
# Global Overrides (Admin)
# =========================
@app.route("/api/overrides", methods=["GET"])
def api_get_overrides():
    d = ensure_keys(load_data())
    return jsonify({
        "allowlist": d.get("allowlist", []),
        "teacher_blocks": d.get("teacher_blocks", [])
    })

@app.route("/api/overrides", methods=["POST"])
def api_save_overrides():
    u = current_user()
    if not u or u["role"] != "admin":
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    b = request.json or {}
    d["allowlist"] = b.get("allowlist", [])
    d["teacher_blocks"] = b.get("teacher_blocks", [])
    save_data(d)
    log_action({"event": "overrides_save"})
    return jsonify({"ok": True})


# =========================
# Poll
# =========================
@app.route("/api/poll", methods=["POST"])
def api_poll():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    body = request.json or {}
    q = (body.get("question") or "").strip()
    opts = [o.strip() for o in (body.get("options") or []) if o and o.strip()]
    if not q or not opts:
        return jsonify({"ok": False, "error": "question and options required"}), 400
    poll_id = "poll_" + str(int(time.time() * 1000))
    d = ensure_keys(load_data())
    d.setdefault("polls", {})[poll_id] = {"question": q, "options": opts, "responses": []}
    d.setdefault("pending_commands", {}).setdefault("*", []).append({
        "type": "poll", "id": poll_id, "question": q, "options": opts
    })
    save_data(d)
    log_action({"event": "poll_create", "poll_id": poll_id})
    return jsonify({"ok": True, "poll_id": poll_id})

@app.route("/api/poll_response", methods=["POST"])
def api_poll_response():
    b = request.json or {}
    poll_id = b.get("poll_id")
    answer = b.get("answer")
    student = (b.get("student") or "").strip()
    if not poll_id:
        return jsonify({"ok": False, "error": "no poll id"}), 400
    d = ensure_keys(load_data())
    if poll_id not in d.get("polls", {}):
        return jsonify({"ok": False, "error": "unknown poll"}), 404
    d["polls"][poll_id].setdefault("responses", []).append({
        "student": student,
        "answer": answer,
        "ts": int(time.time())
    })
    save_data(d)
    log_action({"event": "poll_response", "poll_id": poll_id, "student": student})
    return jsonify({"ok": True})


# =========================
# State (feature flags bucket)
# =========================
@app.route("/api/state")
def api_state():
    d = ensure_keys(load_data())
    yt_rules = {
        "block": get_setting("yt_block_keywords", []),
        "allow": get_setting("yt_allow", []),
        "allow_mode": bool(get_setting("yt_allow_mode", False))
    }
    features = d.setdefault("settings", {}).setdefault("features", {})
    features["youtube_rules"] = yt_rules
    features.setdefault("youtube_filter", True)
    return jsonify(d)


# =========================
# Student: open tabs (explicit)
# =========================
@app.route("/api/student/open_tabs", methods=["POST"])
def api_student_open_tabs():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    b = request.json or {}
    student = (b.get("student") or "").strip()
    urls = b.get("urls") or []
    if not student or not urls:
        return jsonify({"ok": False, "error": "student and urls required"}), 400

    d = load_data()
    pend = d.setdefault("pending_per_student", {})
    arr = pend.setdefault(student, [])
    arr.append({"type": "open_tabs", "urls": urls, "ts": int(time.time())})
    arr[:] = arr[-50:]
    save_data(d)
    return jsonify({"ok": True})


# =========================
# Exam Mode
# =========================
@app.route("/api/exam", methods=["POST"])
def api_exam():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    body = request.json or {}
    action = (body.get("action") or "").strip()
    url = (body.get("url") or "").strip()
    d = ensure_keys(load_data())
    if action == "start":
        if not url:
            return jsonify({"ok": False, "error": "url required"}), 400
        d.setdefault("pending_commands", {}).setdefault("*", []).append({"type": "exam_start", "url": url})
        d.setdefault("exam_state", {})["active"] = True
        d["exam_state"]["url"] = url
        save_data(d)
        log_action({"event": "exam", "action": "start", "url": url})
        return jsonify({"ok": True})
    elif action == "end":
        d.setdefault("pending_commands", {}).setdefault("*", []).append({"type": "exam_end"})
        d.setdefault("exam_state", {})["active"] = False
        save_data(d)
        log_action({"event": "exam", "action": "end"})
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid action"}), 400

@app.route("/api/exam_violation", methods=["POST"])
def api_exam_violation():
    b = request.json or {}
    student = (b.get("student") or "").strip()
    url = (b.get("url") or "").strip()
    reason = (b.get("reason") or "tab_violation").strip()
    if not student:
        return jsonify({"ok": False, "error": "student required"}), 400
    d = ensure_keys(load_data())
    d.setdefault("exam_violations", []).append({
        "student": student, "url": url, "reason": reason, "ts": int(time.time())
    })
    d["exam_violations"] = d["exam_violations"][-500:]
    save_data(d)
    log_action({"event": "exam_violation", "student": student, "reason": reason})
    return jsonify({"ok": True})

@app.route("/api/exam_violations", methods=["GET"])
def api_exam_violations():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    d = ensure_keys(load_data())
    return jsonify({"ok": True, "items": d.get("exam_violations", [])[-200:]})

@app.route("/api/exam_violations/clear", methods=["POST"])
def api_exam_violations_clear():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    b = request.json or {}
    student = (b.get("student") or "").strip()
    d = ensure_keys(load_data())
    if student:
        d["exam_violations"] = [v for v in d.get("exam_violations", []) if v.get("student") != student]
    else:
        d["exam_violations"] = []
    save_data(d)
    log_action({"event": "exam_violations_clear", "student": student or "*"})
    return jsonify({"ok": True})


# =========================
# Notify
# =========================
@app.route("/api/notify", methods=["POST"])
def api_notify():
    u = current_user()
    if not u or u["role"] not in ("teacher", "admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    b = request.json or {}
    title = (b.get("title") or "G School")[:120]
    message = (b.get("message") or "")[:500]
    d = ensure_keys(load_data())
    d.setdefault("pending_commands", {}).setdefault("*", []).append({
        "type": "notify", "title": title, "message": message
    })
    save_data(d)
    log_action({"event": "notify", "title": title})
    return jsonify({"ok": True})


# =========================
# AI (optional blueprint)
# =========================
try:
    import ai_routes
    app.register_blueprint(ai_routes.ai)
except Exception as _e:
    print("AI routes not loaded:", _e)


# =========================
# Run
# =========================
if __name__ == "__main__":
    # Ensure data.json exists and is sane on boot
    save_data(ensure_keys(load_data()))
    app.run(host="0.0.0.0", port=5000, debug=True)
