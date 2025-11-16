# =========================
# G-SCHOOLS CONNECT BACKEND
# =========================

import os
import json
import time
import sqlite3
import random
import string
import logging
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    send_from_directory,
    abort,
    make_response,
)

from werkzeug.middleware.proxy_fix import ProxyFix

# ---------------------------
# Flask App Init
# ---------------------------

ROOT = os.path.dirname(__file__)
DB_PATH = os.path.join(ROOT, "gschool.db")
STATIC_DIR = os.path.join(ROOT, "static")
TEMPLATES_DIR = os.path.join(ROOT, "templates")

app = Flask(__name__, static_folder=STATIC_DIR, template_folder=TEMPLATES_DIR)
app.secret_key = os.environ.get("G_SCHOOL_SECRET", "dev-secret-change-me")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("g-school")

# Import AI routes blueprint
from ai_routes import ai as ai_blueprint, ensure_schema as ensure_ai_schema, get_setting, set_setting

app.register_blueprint(ai_blueprint)


# ---------------------------
# DB Helpers
# ---------------------------

def _db():
    return sqlite3.connect(DB_PATH)


def ensure_schema():
    """
    Ensure core schema for classes, students, presence, screens, overrides, etc.
    ai_routes.ensure_schema() will create AI-related tables separately.
    """
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS classes(
            id TEXT PRIMARY KEY,
            name TEXT,
            active INTEGER DEFAULT 1,
            focus_mode INTEGER DEFAULT 0,
            paused INTEGER DEFAULT 0,
            chat_enabled INTEGER DEFAULT 1
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS students(
            id TEXT PRIMARY KEY,
            name TEXT,
            class_id TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS presence(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            class_id TEXT,
            last_seen INTEGER,
            last_url TEXT,
            last_title TEXT,
            favicon_url TEXT,
            active_tab INTEGER DEFAULT 1,
            screenshot_path TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS screenshots(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            class_id TEXT,
            ts INTEGER,
            url TEXT,
            title TEXT,
            path TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS timeline(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            class_id TEXT,
            ts INTEGER,
            url TEXT,
            title TEXT,
            favicon_url TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS overrides(
            k TEXT PRIMARY KEY,
            v TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS commands(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            student_id TEXT,
            ts INTEGER,
            payload TEXT,
            consumed INTEGER DEFAULT 0
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS settings(
            k TEXT PRIMARY KEY,
            v TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS attention_checks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            prompt TEXT,
            ts INTEGER
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS attention_responses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_id INTEGER,
            student_id TEXT,
            ts INTEGER,
            response TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS scenes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            name TEXT,
            description TEXT,
            kind TEXT, -- "allow" or "block"
            rules_json TEXT,
            is_default INTEGER DEFAULT 0
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS scene_state(
            class_id TEXT PRIMARY KEY,
            active_scene_id INTEGER,
            active INTEGER DEFAULT 0
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS exam_sessions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            exam_url TEXT,
            started_ts INTEGER,
            ended_ts INTEGER
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS exam_violations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER,
            student_id TEXT,
            ts INTEGER,
            url TEXT,
            title TEXT,
            reason TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS youtube_rules(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            rules_json TEXT
        )
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS doodle_block(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id TEXT,
            enabled INTEGER DEFAULT 0
        )
        """
        )
        conn.commit()

    # Ensure at least one class exists
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM classes")
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO classes(id, name, active, focus_mode, paused, chat_enabled) VALUES (?,?,?,?,?,?)",
                ("period1", "Period 1", 1, 0, 0, 1),
            )
            conn.commit()

    # Ensure AI schema as well
    ensure_ai_schema()


# ---------------------------
# Auth / Session Helpers
# ---------------------------

ADMIN_PASSWORD = os.environ.get("G_SCHOOL_ADMIN_PASS", "admin1234")


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw == ADMIN_PASSWORD:
            session["admin"] = True
            nxt = request.args.get("next") or url_for("teacher")
            return redirect(nxt)
        return render_template("login.html", error="Incorrect password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------
# Basic Pages
# ---------------------------

@app.route("/")
def index():
    return redirect(url_for("teacher"))


@app.route("/teacher")
@require_admin
def teacher():
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, active, focus_mode, paused, chat_enabled FROM classes ORDER BY id")
        rows = cur.fetchall()
    classes = [
        {
            "id": r[0],
            "name": r[1],
            "active": bool(r[2]),
            "focus_mode": bool(r[3]),
            "paused": bool(r[4]),
            "chat_enabled": bool(r[5]),
        }
        for r in rows
    ]
    return render_template("teacher.html", data={"classes": classes})


@app.route("/admin")
@require_admin
def admin():
    ensure_schema()
    # Load global settings
    blocked_redirect = get_setting("blocked_redirect", "https://blocked.gdistrict.org/Gschool%20block")
    chat_enabled = get_setting("chat_enabled", True)
    passcode = get_setting("passcode", "")
    return render_template(
        "admin.html",
        data={
            "settings": {
                "blocked_redirect": blocked_redirect,
                "chat_enabled": chat_enabled,
                "passcode": passcode,
            }
        },
    )


# ---------------------------
# Settings & Overrides
# ---------------------------

@app.route("/api/settings", methods=["POST"])
def api_settings():
    body = request.json or {}
    blocked_redirect = body.get("blocked_redirect")
    if blocked_redirect:
        set_setting("blocked_redirect", blocked_redirect)
    chat_enabled = body.get("chat_enabled")
    if chat_enabled is not None:
        set_setting("chat_enabled", bool(chat_enabled))
    passcode = body.get("passcode")
    if passcode is not None:
        set_setting("passcode", passcode)
    return jsonify({"ok": True})


@app.route("/api/overrides", methods=["GET", "POST"])
def api_overrides():
    ensure_schema()
    if request.method == "POST":
        body = request.json or {}
        allowlist = body.get("allowlist", [])
        teacher_blocks = body.get("teacher_blocks", [])

        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO overrides(k, v) VALUES (?, ?)", ("allowlist", json.dumps(allowlist))
            )
            cur.execute(
                "INSERT OR REPLACE INTO overrides(k, v) VALUES (?, ?)",
                ("teacher_blocks", json.dumps(teacher_blocks)),
            )
            conn.commit()
        return jsonify({"ok": True})

    # GET
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT v FROM overrides WHERE k='allowlist'")
        row = cur.fetchone()
        allowlist = json.loads(row[0]) if row and row[0] else []

        cur.execute("SELECT v FROM overrides WHERE k='teacher_blocks'")
        row = cur.fetchone()
        teacher_blocks = json.loads(row[0]) if row and row[0] else []

    return jsonify({"ok": True, "allowlist": allowlist, "teacher_blocks": teacher_blocks})


# ---------------------------
# Class & Student State APIs
# ---------------------------

@app.route("/api/class/toggle", methods=["POST"])
def api_class_toggle():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    field = body.get("field")
    if field not in ("active", "focus_mode", "paused", "chat_enabled"):
        return jsonify({"ok": False, "error": "invalid field"}), 400
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE classes SET {field} = CASE {field} WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (class_id,))
        conn.commit()
        cur.execute("SELECT id, name, active, focus_mode, paused, chat_enabled FROM classes WHERE id=?", (class_id,))
        row = cur.fetchone()
    if not row:
        return jsonify({"ok": False, "error": "class not found"}), 404
    return jsonify(
        {
            "ok": True,
            "class": {
                "id": row[0],
                "name": row[1],
                "active": bool(row[2]),
                "focus_mode": bool(row[3]),
                "paused": bool(row[4]),
                "chat_enabled": bool(row[5]),
            },
        }
    )


@app.route("/api/class/set", methods=["POST"])
def api_class_set():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    ensure_schema()
    updates = {}
    for key in ("active", "focus_mode", "paused", "chat_enabled"):
        if key in body:
            updates[key] = 1 if body[key] else 0
    if not updates:
        return jsonify({"ok": False, "error": "no fields"}), 400
    with _db() as conn:
        cur = conn.cursor()
        for k, v in updates.items():
            cur.execute(f"UPDATE classes SET {k}=? WHERE id=?", (v, class_id))
        conn.commit()
        cur.execute("SELECT id, name, active, focus_mode, paused, chat_enabled FROM classes WHERE id=?", (class_id,))
        row = cur.fetchone()
    return jsonify(
        {
            "ok": True,
            "class": {
                "id": row[0],
                "name": row[1],
                "active": bool(row[2]),
                "focus_mode": bool(row[3]),
                "paused": bool(row[4]),
                "chat_enabled": bool(row[5]),
            },
        }
    )


@app.route("/api/presence", methods=["POST"])
def api_presence():
    body = request.json or {}
    student_id = body.get("student_id")
    student_name = body.get("student_name", "")
    class_id = body.get("class_id", "period1")
    url = body.get("url") or ""
    title = body.get("title") or ""
    favicon_url = body.get("favicon_url")
    active_tab = 1 if body.get("active_tab", True) else 0
    screenshot_path = body.get("screenshot_path")

    if not student_id:
        return jsonify({"ok": False, "error": "student_id required"}), 400

    ensure_schema()
    ts = int(time.time())

    with _db() as conn:
        cur = conn.cursor()
        # Upsert student
        cur.execute(
            "INSERT OR IGNORE INTO students(id, name, class_id) VALUES(?,?,?)",
            (student_id, student_name, class_id),
        )
        if student_name:
            cur.execute("UPDATE students SET name=?, class_id=? WHERE id=?", (student_name, class_id, student_id))

        # Upsert presence
        cur.execute(
            """
            INSERT INTO presence(student_id, class_id, last_seen, last_url, last_title, favicon_url, active_tab, screenshot_path)
            VALUES(?,?,?,?,?,?,?,?)
        """,
            (student_id, class_id, ts, url, title, favicon_url, active_tab, screenshot_path),
        )
        conn.commit()

        # Timeline logging
        if url:
            cur.execute(
                """
                INSERT INTO timeline(student_id, class_id, ts, url, title, favicon_url)
                VALUES(?,?,?,?,?,?)
            """,
                (student_id, class_id, ts, url, title, favicon_url),
            )
            conn.commit()

        # Screenshot logging
        if screenshot_path:
            cur.execute(
                """
                INSERT INTO screenshots(student_id, class_id, ts, url, title, path)
                VALUES(?,?,?,?,?,?)
            """,
                (student_id, class_id, ts, url, title, screenshot_path),
            )
            conn.commit()

    return jsonify({"ok": True})


@app.route("/api/presence", methods=["GET"])
@require_admin
def api_presence_get():
    class_id = request.args.get("class_id", "period1")
    ensure_schema()
    cutoff = int(time.time()) - 60  # 1 minute
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT p.student_id, s.name, p.last_seen, p.last_url, p.last_title, p.favicon_url, p.active_tab, p.screenshot_path
            FROM presence p
            LEFT JOIN students s ON s.id = p.student_id
            WHERE p.class_id=? AND p.last_seen >= ?
            ORDER BY s.name, p.student_id
        """,
            (class_id, cutoff),
        )
        rows = cur.fetchall()

    data = []
    for r in rows:
        data.append(
            {
                "student_id": r[0],
                "student_name": r[1] or r[0],
                "last_seen": r[2],
                "last_url": r[3],
                "last_title": r[4],
                "favicon_url": r[5],
                "active_tab": bool(r[6]),
                "screenshot_path": r[7],
            }
        )
    return jsonify({"ok": True, "presence": data})


# ---------------------------
# Screenshots & Timeline APIs
# ---------------------------

@app.route("/shots/<path:filename>")
def shots_file(filename):
    # For demo only; in production you'd secure this
    shots_dir = os.path.join(ROOT, "shots")
    return send_from_directory(shots_dir, filename)


@app.route("/api/screenshots")
@require_admin
def api_screenshots():
    class_id = request.args.get("class_id", "period1")
    student_id = request.args.get("student_id")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        if student_id:
            cur.execute(
                """
                SELECT student_id, ts, url, title, path
                FROM screenshots
                WHERE class_id=? AND student_id=?
                ORDER BY ts DESC LIMIT 200
            """,
                (class_id, student_id),
            )
        else:
            cur.execute(
                """
                SELECT student_id, ts, url, title, path
                FROM screenshots
                WHERE class_id=?
                ORDER BY ts DESC LIMIT 200
            """,
                (class_id,),
            )
        rows = cur.fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "student_id": r[0],
                "ts": r[1],
                "url": r[2],
                "title": r[3],
                "path": r[4],
            }
        )
    return jsonify({"ok": True, "shots": out})


@app.route("/api/timeline")
@require_admin
def api_timeline():
    class_id = request.args.get("class_id", "period1")
    student_id = request.args.get("student_id")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        if student_id:
            cur.execute(
                """
                SELECT student_id, ts, url, title, favicon_url
                FROM timeline
                WHERE class_id=? AND student_id=?
                ORDER BY ts DESC LIMIT 500
            """,
                (class_id, student_id),
            )
        else:
            cur.execute(
                """
                SELECT student_id, ts, url, title, favicon_url
                FROM timeline
                WHERE class_id=?
                ORDER BY ts DESC LIMIT 500
            """,
                (class_id,),
            )
        rows = cur.fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "student_id": r[0],
                "ts": r[1],
                "url": r[2],
                "title": r[3],
                "favicon_url": r[4],
            }
        )
    return jsonify({"ok": True, "timeline": out})


# ---------------------------
# Commands: Focus, Lock, Tabs, etc.
# ---------------------------

def _enqueue_command(class_id, payload, student_id=None):
    ts = int(time.time())
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO commands(class_id, student_id, ts, payload, consumed)
            VALUES(?,?,?,?,0)
        """,
            (class_id, student_id, ts, json.dumps(payload)),
        )
        conn.commit()
        return cur.lastrowid


@app.route("/api/command", methods=["POST"])
def api_command():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    payload = body.get("payload") or {}
    cmd_id = _enqueue_command(class_id, payload, student_id=student_id)
    return jsonify({"ok": True, "id": cmd_id})


@app.route("/api/commands/poll", methods=["POST"])
def api_commands_poll():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    ensure_schema()
    now = int(time.time())
    cutoff = now - 60
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, payload FROM commands
            WHERE class_id=? AND (student_id IS NULL OR student_id=?) AND consumed=0 AND ts>=?
            ORDER BY id ASC
        """,
            (class_id, student_id, cutoff),
        )
        rows = cur.fetchall()
        ids = [r[0] for r in rows]
        if ids:
            cur.execute(
                f"UPDATE commands SET consumed=1 WHERE id IN ({','.join('?' for _ in ids)})",
                ids,
            )
            conn.commit()

    cmds = [json.loads(r[1]) for r in rows]
    return jsonify({"ok": True, "commands": cmds})


@app.route("/api/open_tabs", methods=["POST"])
def api_open_tabs():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    urls = body.get("urls") or []
    payload = {"type": "open_tabs", "urls": urls}
    _enqueue_command(class_id, payload, student_id=None)
    return jsonify({"ok": True})


@app.route("/api/student/open_tabs", methods=["POST"])
def api_student_open_tabs():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    urls = body.get("urls") or []
    payload = {"type": "open_tabs", "urls": urls}
    _enqueue_command(class_id, payload, student_id=student_id)
    return jsonify({"ok": True})


@app.route("/api/student/tabs_action", methods=["POST"])
def api_student_tabs_action():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    action = body.get("action")
    payload = {"type": "tabs_action", "action": action}
    _enqueue_command(class_id, payload, student_id=student_id)
    return jsonify({"ok": True})


# ---------------------------
# Timeline / Screenshots Commands
# ---------------------------

@app.route("/api/request_screenshot", methods=["POST"])
def api_request_screenshot():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    payload = {"type": "capture_screenshot"}
    _enqueue_command(class_id, payload, student_id=student_id)
    return jsonify({"ok": True})


# ---------------------------
# Attention Check
# ---------------------------

@app.route("/api/attention_check", methods=["POST"])
def api_attention_check():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    prompt = body.get("prompt") or "Are you paying attention?"
    ensure_schema()
    ts = int(time.time())
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO attention_checks(class_id, prompt, ts) VALUES(?,?,?)",
            (class_id, prompt, ts),
        )
        check_id = cur.lastrowid
        conn.commit()

    payload = {"type": "attention_check", "check_id": check_id, "prompt": prompt}
    _enqueue_command(class_id, payload, student_id=None)
    return jsonify({"ok": True, "check_id": check_id})


@app.route("/api/attention_response", methods=["POST"])
def api_attention_response():
    body = request.json or {}
    check_id = body.get("check_id")
    student_id = body.get("student_id")
    response = body.get("response", "")
    if not check_id or not student_id:
        return jsonify({"ok": False, "error": "missing"}), 400
    ts = int(time.time())
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO attention_responses(check_id, student_id, ts, response)
            VALUES(?,?,?,?)
        """,
            (check_id, student_id, ts, response),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/attention_results")
@require_admin
def api_attention_results():
    class_id = request.args.get("class_id", "period1")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, prompt, ts FROM attention_checks
            WHERE class_id=?
            ORDER BY ts DESC LIMIT 10
        """,
            (class_id,),
        )
        checks = cur.fetchall()
        out = []
        for cid, prompt, ts in checks:
            cur.execute(
                """
                SELECT student_id, ts, response FROM attention_responses
                WHERE check_id=?
                ORDER BY ts ASC
            """,
                (cid,),
            )
            rs = cur.fetchall()
            out.append(
                {
                    "check_id": cid,
                    "prompt": prompt,
                    "ts": ts,
                    "responses": [
                        {"student_id": r[0], "ts": r[1], "response": r[2]} for r in rs
                    ],
                }
            )

    return jsonify({"ok": True, "checks": out})


# ---------------------------
# Scene / Focus Plans
# ---------------------------

@app.route("/api/scenes", methods=["GET", "POST"])
@require_admin
def api_scenes():
    class_id = request.args.get("class_id") or (request.json or {}).get("class_id") or "period1"
    ensure_schema()
    if request.method == "POST":
        body = request.json or {}
        name = body.get("name")
        description = body.get("description") or ""
        kind = body.get("kind") or "allow"
        rules = body.get("rules") or []
        if not name:
            return jsonify({"ok": False, "error": "name required"}), 400
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scenes(class_id, name, description, kind, rules_json)
                VALUES(?,?,?,?,?)
            """,
                (class_id, name, description, kind, json.dumps(rules)),
            )
            conn.commit()
            scene_id = cur.lastrowid
        return jsonify({"ok": True, "id": scene_id})

    # GET
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, name, description, kind, rules_json, is_default
            FROM scenes
            WHERE class_id=?
            ORDER BY id ASC
        """,
            (class_id,),
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "name": r[1],
                "description": r[2],
                "kind": r[3],
                "rules": json.loads(r[4] or "[]"),
                "is_default": bool(r[5]),
            }
        )
    return jsonify({"ok": True, "scenes": out})


@app.route("/api/scenes/<int:scene_id>", methods=["PUT", "DELETE"])
@require_admin
def api_scene_update(scene_id):
    ensure_schema()
    if request.method == "DELETE":
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM scenes WHERE id=?", (scene_id,))
            conn.commit()
        return jsonify({"ok": True})

    # PUT
    body = request.json or {}
    name = body.get("name")
    description = body.get("description")
    kind = body.get("kind")
    rules = body.get("rules")

    sets = []
    vals = []
    if name is not None:
        sets.append("name=?")
        vals.append(name)
    if description is not None:
        sets.append("description=?")
        vals.append(description)
    if kind is not None:
        sets.append("kind=?")
        vals.append(kind)
    if rules is not None:
        sets.append("rules_json=?")
        vals.append(json.dumps(rules))

    if not sets:
        return jsonify({"ok": False, "error": "no fields"}), 400

    vals.append(scene_id)
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE scenes SET {', '.join(sets)} WHERE id=?", vals)
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/scenes/default", methods=["POST"])
@require_admin
def api_scenes_default():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    scene_id = body.get("scene_id")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE scenes SET is_default=0 WHERE class_id=?", (class_id,))
        if scene_id:
            cur.execute(
                "UPDATE scenes SET is_default=1 WHERE class_id=? AND id=?",
                (class_id, scene_id),
            )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/scenes/state", methods=["GET", "POST"])
def api_scenes_state():
    class_id = request.args.get("class_id") or (request.json or {}).get("class_id") or "period1"
    ensure_schema()
    if request.method == "POST":
        body = request.json or {}
        active_scene_id = body.get("active_scene_id")
        active = 1 if body.get("active") else 0
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO scene_state(class_id, active_scene_id, active)
                VALUES(?,?,?)
            """,
                (class_id, active_scene_id, active),
            )
            conn.commit()
        return jsonify({"ok": True})

    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT active_scene_id, active FROM scene_state WHERE class_id=?",
            (class_id,),
        )
        row = cur.fetchone()
    if not row:
        return jsonify({"ok": True, "state": None})
    return jsonify(
        {"ok": True, "state": {"active_scene_id": row[0], "active": bool(row[1])}}
    )


@app.route("/api/scenes/export")
@require_admin
def api_scenes_export():
    class_id = request.args.get("class_id", "period1")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, name, description, kind, rules_json, is_default
            FROM scenes
            WHERE class_id=?
            ORDER BY id ASC
        """,
            (class_id,),
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "name": r[1],
                "description": r[2],
                "kind": r[3],
                "rules": json.loads(r[4] or "[]"),
                "is_default": bool(r[5]),
            }
        )
    return jsonify({"ok": True, "scenes": out})


@app.route("/api/scenes/import", methods=["POST"])
@require_admin
def api_scenes_import():
  body = request.json or {}
  class_id = body.get("class_id", "period1")
  scenes = body.get("scenes") or []
  ensure_schema()
  with _db() as conn:
      cur = conn.cursor()
      for s in scenes:
          name = s.get("name")
          if not name:
              continue
          description = s.get("description") or ""
          kind = s.get("kind") or "allow"
          rules = s.get("rules") or []
          is_default = 1 if s.get("is_default") else 0
          cur.execute(
              """
              INSERT INTO scenes(class_id, name, description, kind, rules_json, is_default)
              VALUES(?,?,?,?,?,?)
          """,
              (class_id, name, description, kind, json.dumps(rules), is_default),
          )
      conn.commit()
  return jsonify({"ok": True})


# ---------------------------
# Exam Mode
# ---------------------------

@app.route("/api/exam", methods=["POST"])
def api_exam():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    action = body.get("action")
    ensure_schema()
    ts = int(time.time())
    if action == "start":
        exam_url = body.get("exam_url")
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO exam_sessions(class_id, exam_url, started_ts, ended_ts)
                VALUES(?,?,?,NULL)
            """,
                (class_id, exam_url, ts),
            )
            exam_id = cur.lastrowid
            conn.commit()
        payload = {"type": "exam_start", "exam_url": exam_url, "exam_id": exam_id}
        _enqueue_command(class_id, payload, student_id=None)
        return jsonify({"ok": True, "exam_id": exam_id})

    if action == "end":
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id FROM exam_sessions
                WHERE class_id=? AND ended_ts IS NULL
                ORDER BY started_ts DESC LIMIT 1
            """,
                (class_id,),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "no active exam"}), 400
            exam_id = row[0]
            cur.execute(
                "UPDATE exam_sessions SET ended_ts=? WHERE id=?",
                (ts, exam_id),
            )
            conn.commit()
        payload = {"type": "exam_end", "exam_id": exam_id}
        _enqueue_command(class_id, payload, student_id=None)
        return jsonify({"ok": True})

    return jsonify({"ok": False, "error": "invalid action"}), 400


@app.route("/api/exam_violations", methods=["POST"])
def api_exam_violations():
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")
    url = body.get("url", "")
    title = body.get("title", "")
    reason = body.get("reason", "")
    exam_id = body.get("exam_id")
    if not exam_id:
        return jsonify({"ok": False, "error": "exam_id required"}), 400
    ts = int(time.time())
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO exam_violations(exam_id, student_id, ts, url, title, reason)
            VALUES(?,?,?,?,?,?)
        """,
            (exam_id, student_id, ts, url, title, reason),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/exam_violations", methods=["GET"])
@require_admin
def api_exam_violations_get():
    class_id = request.args.get("class_id", "period1")
    ensure_schema()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT e.id, e.class_id, e.exam_url, e.started_ts, e.ended_ts
            FROM exam_sessions e
            WHERE e.class_id=?
            ORDER BY e.started_ts DESC LIMIT 5
        """,
            (class_id,),
        )
        sessions = cur.fetchall()
        out = []
        for s in sessions:
            exam_id = s[0]
            cur.execute(
                """
                SELECT student_id, ts, url, title, reason
                FROM exam_violations
                WHERE exam_id=?
                ORDER BY ts ASC
            """,
                (exam_id,),
            )
            vs = cur.fetchall()
            out.append(
                {
                    "exam_id": exam_id,
                    "class_id": s[1],
                    "exam_url": s[2],
                    "started_ts": s[3],
                    "ended_ts": s[4],
                    "violations": [
                        {
                            "student_id": v[0],
                            "ts": v[1],
                            "url": v[2],
                            "title": v[3],
                            "reason": v[4],
                        }
                        for v in vs
                    ],
                }
            )
    return jsonify({"ok": True, "sessions": out})


# ---------------------------
# YouTube & Doodle Settings
# ---------------------------

@app.route("/api/youtube_rules", methods=["GET", "POST"])
def api_youtube_rules():
    class_id = request.args.get("class_id") or (request.json or {}).get("class_id") or "period1"
    ensure_schema()
    if request.method == "POST":
        body = request.json or {}
        rules = body.get("rules") or {}
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO youtube_rules(class_id, rules_json)
                VALUES(?,?)
            """,
                (class_id, json.dumps(rules)),
            )
            conn.commit()
        return jsonify({"ok": True})

    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT rules_json FROM youtube_rules WHERE class_id=?",
            (class_id,),
        )
        row = cur.fetchone()
    rules = json.loads(row[0]) if row and row[0] else {}
    return jsonify({"ok": True, "rules": rules})


@app.route("/api/doodle_block", methods=["GET", "POST"])
def api_doodle_block():
    class_id = request.args.get("class_id") or (request.json or {}).get("class_id") or "period1"
    ensure_schema()
    if request.method == "POST":
        body = request.json or {}
        enabled = 1 if body.get("enabled") else 0
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO doodle_block(class_id, enabled)
                VALUES(?,?)
            """,
                (class_id, enabled),
            )
            conn.commit()
        return jsonify({"ok": True})

    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT enabled FROM doodle_block WHERE class_id=?",
            (class_id,),
        )
        row = cur.fetchone()
    enabled = bool(row[0]) if row else False
    return jsonify({"ok": True, "enabled": enabled})


# ---------------------------
# Policy Endpoint for Extension
# ---------------------------

@app.route("/api/policy", methods=["POST"])
def api_policy():
    """
    Return policy for extension: class state, overrides, scenes, exam, youtube, doodle, etc.
    """
    body = request.json or {}
    class_id = body.get("class_id", "period1")
    student_id = body.get("student_id")

    ensure_schema()

    with _db() as conn:
        cur = conn.cursor()

        # Class row
        cur.execute(
            "SELECT id, name, active, focus_mode, paused, chat_enabled FROM classes WHERE id=?",
            (class_id,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "error": "class not found"}), 404
        class_info = {
            "id": row[0],
            "name": row[1],
            "active": bool(row[2]),
            "focus_mode": bool(row[3]),
            "paused": bool(row[4]),
            "chat_enabled": bool(row[5]),
        }

        # Overrides
        cur.execute("SELECT v FROM overrides WHERE k='allowlist'")
        row = cur.fetchone()
        allowlist = json.loads(row[0]) if row and row[0] else []

        cur.execute("SELECT v FROM overrides WHERE k='teacher_blocks'")
        row = cur.fetchone()
        teacher_blocks = json.loads(row[0]) if row and row[0] else []

        # Active scene state
        cur.execute(
            "SELECT active_scene_id, active FROM scene_state WHERE class_id=?",
            (class_id,),
        )
        row = cur.fetchone()
        active_scene = None
        if row and row[0] and row[1]:
            scene_id = row[0]
            cur.execute(
                """
                SELECT id, name, description, kind, rules_json
                FROM scenes WHERE id=?
            """,
                (scene_id,),
            )
            s = cur.fetchone()
            if s:
                active_scene = {
                    "id": s[0],
                    "name": s[1],
                    "description": s[2],
                    "kind": s[3],
                    "rules": json.loads(s[4] or "[]"),
                }

        # Exam mode
        cur.execute(
            """
            SELECT id, exam_url, started_ts, ended_ts
            FROM exam_sessions
            WHERE class_id=? AND ended_ts IS NULL
            ORDER BY started_ts DESC LIMIT 1
        """,
            (class_id,),
        )
        row = cur.fetchone()
        exam = None
        if row:
            exam = {
                "id": row[0],
                "exam_url": row[1],
                "started_ts": row[2],
            }

        # YouTube rules
        cur.execute("SELECT rules_json FROM youtube_rules WHERE class_id=?", (class_id,))
        row = cur.fetchone()
        youtube_rules = json.loads(row[0]) if row and row[0] else {}

        # Doodle block
        cur.execute("SELECT enabled FROM doodle_block WHERE class_id=?", (class_id,))
        row = cur.fetchone()
        doodle_block_enabled = bool(row[0]) if row else False

        # Passcode
        passcode = get_setting("passcode", "")

    return jsonify(
        {
            "ok": True,
            "class": class_info,
            "allowlist": allowlist,
            "teacher_blocks": teacher_blocks,
            "scene": active_scene,
            "exam": exam,
            "youtube_rules": youtube_rules,
            "doodle_block": doodle_block_enabled,
            "passcode": passcode,
            "chat_enabled": class_info["chat_enabled"],
        }
    )


# ---------------------------
# Static & Misc
# ---------------------------

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


@app.errorhandler(404)
def not_found(e):
    return make_response(render_template("404.html"), 404)


# ---------------------------
# Main
# ---------------------------

if __name__ == "__main__":
    ensure_schema()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
