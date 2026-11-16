"""Small task-board app used as the lab 7 system under test.

The app uses Python's standard library and SQLite. It is intended for a local
teaching environment and binds to loopback through the supplied Docker Compose
file.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse


HOST = os.getenv("APP_HOST", "0.0.0.0")
PORT = int(os.getenv("APP_PORT", "8787"))
DB_PATH = os.getenv("APP_DB", "/data/taskboard.sqlite3")
DATA_DIR = os.path.dirname(DB_PATH) or "."
BOOTSTRAP_TOKEN_PATH = os.path.join(DATA_DIR, "bootstrap-token")
RESET_OUTBOX_PATH = os.path.join(DATA_DIR, "reset-outbox.txt")
STATUSES = ("To Do", "In Progress", "Done")
ROLES = ("admin", "member", "guest")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def initialize():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','member','guest')),
            active INTEGER NOT NULL DEFAULT 1,
            consent INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            deadline TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'To Do' CHECK(status IN ('To Do','In Progress','Done')),
            tags TEXT NOT NULL DEFAULT '[]',
            owner_id INTEGER NOT NULL REFERENCES users(id),
            assignee_id INTEGER REFERENCES users(id),
            deleted_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            task_id INTEGER NOT NULL REFERENCES tasks(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            task_id INTEGER REFERENCES tasks(id),
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS task_owner_idx ON tasks(owner_id, deleted_at);
        CREATE INDEX IF NOT EXISTS task_assignee_idx ON tasks(assignee_id, deleted_at);
        CREATE INDEX IF NOT EXISTS comment_task_idx ON comments(task_id, created_at);
        """)
        admin_count = con.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
    if not admin_count and not os.path.exists(BOOTSTRAP_TOKEN_PATH):
        fd = os.open(BOOTSTRAP_TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as token_file:
            token_file.write(secrets.token_urlsafe(32))


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def esc(value):
    return html.escape(str(value or ""), quote=True)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return salt.hex() + "$" + digest.hex()


def valid_password(password: str) -> bool:
    return len(password) >= 8 and any(c.isalpha() for c in password) and any(c.isdigit() for c in password)


def valid_email(email: str) -> bool:
    pattern = r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
    return len(email) <= 254 and re.fullmatch(pattern, email, flags=re.IGNORECASE) is not None


def tags_from_text(text: str) -> list[str]:
    out = []
    for raw in text.split(","):
        tag = " ".join(raw.strip().split())
        if tag and tag.casefold() not in {x.casefold() for x in out}:
            out.append(tag[:40])
    return out


def audit(con, user_id, task_id, action, details=""):
    con.execute("INSERT INTO audit(user_id,task_id,action,details,created_at) VALUES(?,?,?,?,?)", (user_id, task_id, action, details[:300], now()))


class App(BaseHTTPRequestHandler):
    server_version = "Lab7TaskBoard/1.0"

    def log_message(self, fmt, *args):
        message = fmt % args
        message = re.sub(r'("(?:GET|POST|HEAD|PUT|DELETE) )([^ ?"]+)\?[^ " ]*', r'\1\2?[redacted]', message)
        logging.info("%s %s", self.address_string(), message)

    def send(self, status, body, headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        headers = list(headers or [])
        if not any(name.lower() == "content-type" for name, _ in headers):
            headers.append(("Content-Type", "text/html; charset=utf-8" if isinstance(body, str) else "application/json; charset=utf-8"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path):
        self.send(303, "", [("Location", path)])

    def fields(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64_000:
            raise ValueError("The form is too large.")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[-1] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def session(self, con):
        cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        if "lab7_session" not in cookie:
            return None
        row = con.execute("SELECT u.*,s.token,s.csrf,s.created_at AS session_created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (cookie["lab7_session"].value,)).fetchone()
        if row and int(time.time()) - row["session_created_at"] >= 8 * 60 * 60:
            con.execute("DELETE FROM sessions WHERE token=?", (row["token"],))
            return None
        return row if row and row["active"] else None

    def json_response(self, status, payload):
        self.send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), [("Content-Type", "application/json; charset=utf-8")])

    def csrf_form(self, user):
        return f'<input type="hidden" name="csrf" value="{esc(user["csrf"])}">'

    def page(self, title, body, user=None, message="", status=200):
        nav = '<a href="/">Board</a> <a href="/tasks/new">New task</a> <a href="/api/docs">API</a> <a href="/profile">Profile</a>'
        if user:
            if user["role"] == "admin":
                nav += ' <a href="/admin/users">Users</a> <a href="/audit">Audit log</a> <a href="/trash">Trash</a>'
            nav += f'<span class="identity">{esc(user["name"])} ({esc(user["role"])})</span><form class="inline" method="post" action="/logout">{self.csrf_form(user)}<button>Log out</button></form>'
        else:
            nav = '<a href="/login">Log in</a> <a href="/register">Register</a>'
        alert = f'<p class="notice" role="status">{esc(message)}</p>' if message else ""
        html_page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)} - Task Board</title>
        <style>
        :root{{font-family:system-ui,Segoe UI,sans-serif;color:#17212b;background:#f3f6f9}}body{{margin:0}}header{{background:#17324d;color:#fff;padding:1rem 3vw;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}}header a{{color:#fff}}header strong{{font-size:1.1rem;margin-right:auto}}nav{{display:flex;gap:.8rem;align-items:center;flex-wrap:wrap}}.identity{{font-size:.9rem;color:#e2edf7}}main{{max-width:1100px;margin:1.6rem auto;padding:0 1rem}}h1{{font-size:1.7rem}}a{{color:#075985}}button,.button{{display:inline-block;border:0;border-radius:5px;background:#075985;color:#fff;padding:.58rem .85rem;text-decoration:none;font:inherit;cursor:pointer}}button.secondary,.secondary{{background:#465667}}button.danger{{background:#a32626}}input,textarea,select{{box-sizing:border-box;width:100%;padding:.62rem;border:1px solid #8091a0;border-radius:4px;font:inherit;background:white}}label{{display:block;margin:.8rem 0 .3rem;font-weight:600}}form.block{{max-width:600px}}.inline{{display:inline-flex;gap:.4rem;align-items:center;margin:0}}.inline input,.inline select{{width:auto}}.notice{{background:#e1f3ea;border-left:4px solid #198754;padding:.8rem}}.error{{background:#ffebeb;border-left:4px solid #b42318;padding:.8rem}}.card,.panel{{background:#fff;border:1px solid #d4dde5;border-radius:7px;padding:1rem;margin:.8rem 0;box-shadow:0 1px 2px #0000000a}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.8rem}}.tags span{{display:inline-block;background:#e8eef5;border-radius:1rem;padding:.15rem .55rem;margin:.15rem}}table{{border-collapse:collapse;width:100%;background:white}}th,td{{text-align:left;padding:.7rem;border-bottom:1px solid #d7e0e8;vertical-align:top}}th{{background:#e8eef5}}.muted{{color:#4d5b68}}.status{{font-weight:600}}.actions{{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.8rem}}.comment{{border-bottom:1px solid #ddd;padding:.55rem 0}}.help{{font-size:.9rem;color:#405364}}@media(max-width:600px){{header{{align-items:flex-start}}main{{margin:1rem auto}}table{{font-size:.9rem}}th,td{{padding:.45rem}}}}
        </style></head><body><header><strong>Task Board</strong><nav>{nav}</nav></header><main><h1>{esc(title)}</h1>{alert}{body}</main></body></html>'''
        self.send(status, html_page)

    def error(self, user, message, status=400, title="Error"):
        self.page(title, f'<p class="error" role="alert">{esc(message)}</p><p><a href="/">Return to the task list</a></p>', user, status=status)

    def require_csrf(self, user, fields):
        return bool(user and hmac.compare_digest(fields.get("csrf", ""), user["csrf"]))

    def current_user(self, con, path):
        user = self.session(con)
        if not user:
            self.redirect("/login?next=" + quote(path, safe="/"))
            return None
        return user

    def task_by_id(self, con, task_id, include_deleted=False):
        where = "t.id=?" if include_deleted else "t.id=? AND t.deleted_at IS NULL"
        return con.execute(f"SELECT t.*,o.name owner_name,a.name assignee_name FROM tasks t JOIN users o ON o.id=t.owner_id LEFT JOIN users a ON a.id=t.assignee_id WHERE {where}", (task_id,)).fetchone()

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        with db() as con:
            user = self.session(con)
            admin_count = con.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
            if path == "/health":
                self.json_response(200, {"status": "ok", "app": "lab7-taskboard"})
                return
            if path == "/api/docs":
                self.page("Test project API", '<section class="panel"><p>Use the API to read tasks after signing in.</p><table><tr><th>Method</th><th>Path</th><th>Success response</th></tr><tr><td>GET</td><td>/api/tasks</td><td>200, a list of tasks</td></tr><tr><td>GET</td><td>/api/tasks/{id}</td><td>200, one task</td></tr><tr><td>GET</td><td>/health</td><td>200, service status</td></tr></table><p>Unauthenticated requests to /api/tasks return 401. Responses never include passwords or test account data.</p></section>', user)
                return
            if path == "/api/tasks" or path.startswith("/api/tasks/"):
                if not user:
                    self.json_response(401, {"error": "authentication_required"})
                    return
                if path == "/api/tasks":
                    records = con.execute("SELECT id,title,description,deadline,status,tags,owner_id,assignee_id,updated_at FROM tasks WHERE deleted_at IS NULL ORDER BY id").fetchall()
                    self.json_response(200, [dict(r, tags=json.loads(r["tags"])) for r in records])
                    return
                suffix = path.removeprefix("/api/tasks/")
                if suffix.isdigit():
                    task = con.execute("SELECT id,title,description,deadline,status,tags,owner_id,assignee_id,updated_at FROM tasks WHERE id=? AND deleted_at IS NULL", (int(suffix),)).fetchone()
                    if task:
                        self.json_response(200, dict(task, tags=json.loads(task["tags"])))
                    else:
                        self.json_response(404, {"error": "not_found"})
                    return
            if path == "/setup":
                if admin_count:
                    self.redirect("/login")
                    return
                self.page("Initial setup", self.setup_form())
                return
            if path == "/login":
                if user:
                    self.redirect("/")
                    return
                self.page("Log in", self.login_form(), message=query.get("message", [""])[0])
                return
            if path == "/register":
                self.page("Registration", self.register_form())
                return
            if path == "/password/reset":
                self.page("Password reset", self.reset_request_form())
                return
            if path == "/password/reset/confirm":
                token = query.get("token", [""])[0]
                row = con.execute("SELECT * FROM reset_tokens WHERE token=?", (token,)).fetchone()
                if not row or row["used"] or row["expires_at"] < int(time.time()):
                    self.page("Password reset", '<p class="error">This link is invalid or has expired.</p><p><a href="/password/reset">Request a new link</a></p>', user)
                    return
                self.page("New password", self.reset_confirm_form(token), user)
                return
            if not user:
                self.redirect("/login?next=" + quote(path, safe="/"))
                return
            if path == "/":
                self.board(con, user, query.get("message", [""])[0])
                return
            if path == "/tasks/new":
                if user["role"] == "guest":
                    self.error(user, "Guests cannot create tasks.", 403)
                    return
                self.page("New task", self.task_form(con, user))
                return
            if path.startswith("/tasks/"):
                parts = path.strip("/").split("/")
                if len(parts) == 2 and parts[1].isdigit():
                    self.task_detail(con, user, int(parts[1]))
                    return
                if len(parts) == 3 and parts[1].isdigit() and parts[2] == "edit":
                    task = self.task_by_id(con, int(parts[1]))
                    if not task:
                        self.error(user, "Task not found.", 404)
                    elif not self.can_manage(user, task):
                        self.error(user, "Only the task owner or an administrator can edit this task.", 403)
                    else:
                        self.page("Edit task", self.task_form(con, user, task))
                    return
            if path == "/profile":
                self.page("Profile", f'<section class="panel"><p>Name: {esc(user["name"])}</p><p>Email: {esc(user["email"])}</p><p>Role: {esc(user["role"])}</p><p>Status: {"Active" if user["active"] else "Inactive"}</p><a class="button" href="/password/reset">Change password</a></section>', user)
                return
            if path == "/audit":
                if user["role"] != "admin":
                    self.error(user, "Only an administrator can access the audit log.", 403)
                    return
                self.audit_page(con, user)
                return
            if path == "/admin/users":
                if user["role"] != "admin":
                    self.error(user, "Only an administrator can manage users.", 403)
                    return
                self.users_page(con, user)
                return
            if path == "/trash":
                if user["role"] != "admin":
                    self.error(user, "Only an administrator can restore tasks.", 403)
                    return
                rows = con.execute("SELECT t.*,u.name owner_name FROM tasks t JOIN users u ON u.id=t.owner_id WHERE t.deleted_at IS NOT NULL ORDER BY t.deleted_at DESC").fetchall()
                body = "<p>Deleted tasks can be restored.</p>" + "".join(f'<div class="card"><strong>{esc(t["title"])}</strong><p>{esc(t["deleted_at"])}</p><form method="post" action="/tasks/{t["id"]}/restore">{self.csrf_form(user)}<button>Restore</button></form></div>' for t in rows) or '<p class="panel">The trash is empty.</p>'
                self.page("Restore tasks", body)
                return
            self.error(user, "Page not found.", 404)

    def setup_form(self):
        return f'''<p class="help">Create a local administrator account. The one-time setup token is available inside the container.</p><form class="block" method="post" action="/setup">
        <label for="bootstrap_token">One-time setup token</label><input id="bootstrap_token" name="bootstrap_token" required autocomplete="off">
        <label for="name">Name</label><input id="name" name="name" required maxlength="80"><label for="email">Email</label><input id="email" type="email" name="email" required>
        <label for="password">Password</label><input id="password" type="password" name="password" minlength="8" required><p class="help">At least 8 characters, including a letter and a number.</p><button>Create administrator</button></form>'''

    def login_form(self):
        return '''<form class="block" method="post" action="/login"><label for="email">Email</label><input id="email" type="email" name="email" autocomplete="username" required><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required><div class="actions"><button>Log in</button><a class="button secondary" href="/password/reset">Forgot password?</a></div></form>'''

    def register_form(self):
        return '''<form class="block" method="post" action="/register"><label for="name">Name</label><input id="name" name="name" maxlength="80" required><label for="email">Email</label><input id="email" type="email" name="email" required><label for="password">Password</label><input id="password" type="password" name="password" minlength="8" required><label><input type="checkbox" name="consent" value="yes" required style="width:auto"> I agree to the processing of test data</label><button>Register</button></form>'''

    def reset_request_form(self):
        return '''<form class="block" method="post" action="/password/reset"><label for="email">Account email</label><input id="email" type="email" name="email" required><button>Create password reset link</button></form>'''

    def reset_confirm_form(self, token):
        return f'''<form class="block" method="post" action="/password/reset/confirm"><input type="hidden" name="token" value="{esc(token)}"><label for="password">New password</label><input id="password" type="password" name="password" minlength="8" required><button>Save password</button></form>'''

    def task_form(self, con, user, task=None):
        users = con.execute("SELECT id,name,email FROM users WHERE active=1 AND role!='guest' ORDER BY name").fetchall()
        current_assignee = task["assignee_id"] if task else user["id"]
        selected_status = task["status"] if task else "To Do"
        title = esc(task["title"] if task else "")
        description = esc(task["description"] if task else "")
        deadline = esc(task["deadline"] if task else "")
        tag_text = esc(", ".join(json.loads(task["tags"]) if task else []))
        user_options = '<option value="">Unassigned</option>' + "".join(f'<option value="{u["id"]}" {"selected" if u["id"] == current_assignee else ""}>{esc(u["name"])} ({esc(u["email"])})</option>' for u in users)
        status_options = "".join(f'<option {"selected" if s == selected_status else ""}>{esc(s)}</option>' for s in STATUSES)
        may_change_status = user["role"] == "admin" or (user["role"] == "member" and task and task["assignee_id"] == user["id"])
        status_control = f'<select id="status" name="status">{status_options}</select>' if may_change_status or not task else f'<input type="hidden" name="status" value="{esc(selected_status)}"><select id="status" disabled>{status_options}</select>'
        action = f'/tasks/{task["id"]}/edit' if task else "/tasks/create"
        method = f'<input type="hidden" name="id" value="{task["id"]}">' if task else ""
        autosave = f'''<script>
        (() => {{ const form=document.getElementById('task-form'); if(!form || !form.dataset.autosave) return; let timer;
        form.addEventListener('input', () => {{ clearTimeout(timer); timer=setTimeout(async () => {{
          const result=document.getElementById('save-state'); const body=new URLSearchParams(new FormData(form));
          const response=await fetch(form.dataset.autosave, {{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body}});
          result.textContent=response.ok?'Changes saved automatically':'Could not save changes';
        }}, 500); }}); }})();</script>''' if task else ""
        autosave_attr = f' data-autosave="/tasks/{task["id"]}/autosave"' if task else ""
        return f'''<form id="task-form" class="block" method="post" action="{action}"{autosave_attr}>{self.csrf_form(user)}{method}
        <label for="title">Title</label><input id="title" name="title" maxlength="160" value="{title}" required>
        <label for="description">Description</label><textarea id="description" name="description" rows="4" maxlength="4000">{description}</textarea>
        <label for="deadline">Due date</label><input id="deadline" type="date" name="deadline" value="{deadline}">
        <label for="assignee">Assignee</label><select id="assignee" name="assignee_id">{user_options}</select>
        <label for="status">Status</label>{status_control}
        <label for="tags">Tags</label><input id="tags" name="tags" value="{tag_text}" placeholder="For example: work, urgent">
        <p class="help">Separate multiple tags with commas.</p><button>Save</button> <a href="/">Cancel</a><p id="save-state" class="help" role="status"></p></form>{autosave}'''

    def board(self, con, user, message=""):
        rows = con.execute("SELECT t.*,o.name owner_name,a.name assignee_name FROM tasks t JOIN users o ON o.id=t.owner_id LEFT JOIN users a ON a.id=t.assignee_id WHERE t.deleted_at IS NULL ORDER BY t.updated_at DESC,t.id DESC").fetchall()
        filter_status = parse_qs(urlparse(self.path).query).get("status", [""])[0]
        if filter_status in STATUSES:
            rows = [r for r in rows if r["status"] == filter_status]
        options = '<option value="">All statuses</option>' + "".join(f'<option {"selected" if filter_status == s else ""}>{esc(s)}</option>' for s in STATUSES)
        body = f'''<form class="inline" method="get" action="/"><label for="status">Filter by status</label><select id="status" name="status">{options}</select><button>Filter</button></form>'''
        body += '<p><a class="button" href="/tasks/new">Create task</a></p>'
        if not rows:
            body += '<div class="panel">No tasks yet.</div>'
        cards = {status: [] for status in STATUSES}
        for task in rows:
            tags = "".join(f"<span>{esc(x)}</span>" for x in json.loads(task["tags"]))
            actions = f'<a href="/tasks/{task["id"]}">Open</a>'
            if self.can_manage(user, task):
                actions += f' · <a href="/tasks/{task["id"]}/edit">Edit</a>'
            status_form = ""
            if user["role"] == "admin" or (user["role"] == "member" and task["assignee_id"] == user["id"]):
                status_form = f'<form class="inline" method="post" action="/tasks/{task["id"]}/status">{self.csrf_form(user)}<select name="status" aria-label="Status {esc(task["title"])}">' + "".join(f'<option {"selected" if s == task["status"] else ""}>{esc(s)}</option>' for s in STATUSES) + '</select><button>Update</button></form>'
            draggable = user["role"] == "admin" or (user["role"] == "member" and task["assignee_id"] == user["id"])
            cards[task["status"]].append(f'''<article class="card board-card" data-task-id="{task["id"]}" draggable="{"true" if draggable else "false"}"><h2><a href="/tasks/{task["id"]}">{esc(task["title"])}</a></h2><p class="status">{esc(task["status"])}</p><p>{esc(task["description"])}</p><p>Owner: {esc(task["owner_name"])} · Assignee: {esc(task["assignee_name"] or "Not set")} · Due date: {esc(task["deadline"] or "Not set")}</p><div class="tags">{tags}</div><div class="actions">{actions}{status_form}</div></article>''')
        body += '<div class="board-columns">' + "".join(f'<section class="board-column"><h2>{esc(status)}</h2><div class="drop-zone" data-status="{esc(status)}">{"".join(cards[status])}</div></section>' for status in STATUSES) + '</div>'
        body += '''<style>.board-columns{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:.8rem;align-items:start}.board-column{background:#e8eef5;border-radius:7px;padding:.65rem}.drop-zone{min-height:5rem}.board-card[draggable="true"]{cursor:grab}.drop-zone.drag-over{outline:2px dashed #075985;outline-offset:2px}@media(max-width:760px){.board-columns{grid-template-columns:1fr}}</style>
        <script>(()=>{let dragged=null;document.querySelectorAll('.board-card[draggable="true"]').forEach(card=>card.addEventListener('dragstart',e=>{dragged=card;e.dataTransfer.setData('text/plain',card.dataset.taskId)}));document.querySelectorAll('.drop-zone').forEach(zone=>{zone.addEventListener('dragover',e=>{e.preventDefault();zone.classList.add('drag-over')});zone.addEventListener('dragleave',()=>zone.classList.remove('drag-over'));zone.addEventListener('drop',async e=>{e.preventDefault();zone.classList.remove('drag-over');const card=dragged||document.querySelector(`[data-task-id="${e.dataTransfer.getData('text/plain')}"]`);if(!card||!card.querySelector('form[action$="/status"]'))return;const form=card.querySelector('form[action$="/status"]');const body=new URLSearchParams({csrf:form.querySelector('[name="csrf"]').value,status:zone.dataset.status});const response=await fetch(form.action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});if(response.ok)location.reload()})})})();</script>'''
        body += '<p class="help">Only the assigned user or an administrator can change the status.</p>'
        self.page("Task list", body, user, message)

    def can_manage(self, user, task):
        return user["role"] == "admin" or (user["role"] == "member" and user["id"] == task["owner_id"])

    def task_detail(self, con, user, task_id):
        task = self.task_by_id(con, task_id)
        if not task:
            self.error(user, "Task not found.", 404)
            return
        tags = "".join(f"<span>{esc(x)}</span>" for x in json.loads(task["tags"]))
        comments = con.execute("SELECT c.*,u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.task_id=? ORDER BY c.id", (task_id,)).fetchall()
        history = ""
        if user["role"] == "admin":
            events = con.execute("SELECT a.*,u.name FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE a.task_id=? ORDER BY a.id DESC", (task_id,)).fetchall()
            history = '<section class="panel"><h2>Activity history</h2>' + ("".join(f'<p>{esc(e["created_at"])} · {esc(e["name"] or "System")}: {esc(e["action"])} {esc(e["details"])}</p>' for e in events) or "<p>No activity yet.</p>") + "</section>"
        actions = f'<a class="button" href="/tasks/{task_id}/edit">Edit</a>' if self.can_manage(user, task) else ""
        if self.can_manage(user, task):
            actions += f'<form class="inline" method="post" action="/tasks/{task_id}/delete" onsubmit="return confirm(\'Delete this task?\')">{self.csrf_form(user)}<button class="danger">Delete</button></form>'
        comment_form = ""
        if user["role"] != "guest" and user["id"] in (task["owner_id"], task["assignee_id"]) or user["role"] == "admin":
            comment_form = f'<form method="post" action="/tasks/{task_id}/comments">{self.csrf_form(user)}<label for="body">New comment</label><textarea id="body" name="body" rows="3" maxlength="2000" required></textarea><button>Add comment</button></form>'
        body = f'''<section class="panel"><p class="status">Status: {esc(task["status"])}</p><p>{esc(task["description"])}</p><p>Owner: {esc(task["owner_name"])} · Assignee: {esc(task["assignee_name"] or "Unassigned")}</p><p>Due date: {esc(task["deadline"] or "Not set")}</p><div class="tags">{tags}</div><div class="actions">{actions}</div></section><section class="panel"><h2>Comments</h2>'''
        for comment in comments:
            body += f'<div class="comment"><strong>{esc(comment["name"])}</strong> · {esc(comment["created_at"])}<p>{esc(comment["body"])}</p>'
            if user["role"] == "admin" or user["id"] == comment["user_id"]:
                body += f'<details><summary>Edit comment</summary><form method="post" action="/tasks/{task_id}/comments/{comment["id"]}/edit">{self.csrf_form(user)}<textarea name="body" maxlength="2000" required>{esc(comment["body"])}</textarea><button>Save</button></form><form method="post" action="/tasks/{task_id}/comments/{comment["id"]}/delete">{self.csrf_form(user)}<button class="danger">Delete</button></form></details>'
            body += '</div>'
        if not comments:
            body += "<p>No comments yet.</p>"
        body += comment_form + "</section>" + history
        self.page("Task details", body, user)

    def audit_page(self, con, user):
        events = con.execute("SELECT a.*,u.name, t.title FROM audit a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN tasks t ON t.id=a.task_id ORDER BY a.id DESC LIMIT 200").fetchall()
        body = '<div class="panel"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Task</th><th>Details</th></tr></thead><tbody>'
        body += "".join(f'<tr><td>{esc(x["created_at"])}</td><td>{esc(x["name"] or "System")}</td><td>{esc(x["action"])}</td><td>{esc(x["title"] or "-")}</td><td>{esc(x["details"])}</td></tr>' for x in events)
        self.page("Audit log", body + "</tbody></table></div>", user)

    def users_page(self, con, user):
        users = con.execute("SELECT id,name,email,role,active,created_at FROM users ORDER BY id").fetchall()
        body = '<div class="panel"><table><thead><tr><th>User</th><th>Role</th><th>State</th><th>Actions</th></tr></thead><tbody>'
        for u in users:
            role_options = "".join(f'<option value="{r}" {"selected" if r == u["role"] else ""}>{r}</option>' for r in ROLES)
            body += f'<tr><td>{esc(u["name"])}<br>{esc(u["email"])}</td><td><form class="inline" method="post" action="/admin/users/{u["id"]}/role">{self.csrf_form(user)}<select name="role">{role_options}</select><button>Change role</button></form></td><td>{"Active" if u["active"] else "Inactive"}</td><td><form method="post" action="/admin/users/{u["id"]}/toggle">{self.csrf_form(user)}<button class="secondary">{"Deactivate" if u["active"] else "Activate"}</button></form></td></tr>'
        self.page("Users", body + "</tbody></table></div>", user)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            fields = self.fields()
        except ValueError as e:
            self.error(None, str(e), 413)
            return
        with db() as con:
            # Serialize writes so one-time setup/reset and admin invariants cannot race.
            con.execute("BEGIN IMMEDIATE")
            user = self.session(con)
            if path == "/setup":
                if con.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]:
                    self.error(None, "Initial setup has already been completed.", 409)
                    return
                try:
                    with open(BOOTSTRAP_TOKEN_PATH, "r", encoding="utf-8") as token_file:
                        bootstrap_token = token_file.read().strip()
                except OSError:
                    bootstrap_token = ""
                supplied_token = fields.get("bootstrap_token", "")
                if not bootstrap_token or not supplied_token or not hmac.compare_digest(bootstrap_token, supplied_token):
                    self.error(None, "Initial setup is unavailable.", 403)
                    return
                name, email, password = fields.get("name", "").strip(), fields.get("email", "").strip(), fields.get("password", "")
                error = self.validate_user(name, email, password)
                if error:
                    self.page("Initial setup", self.setup_form() + f'<p class="error">{esc(error)}</p>', status=400)
                    return
                cur = con.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)", (name, email, hash_password(password), "admin", now()))
                try:
                    os.remove(BOOTSTRAP_TOKEN_PATH)
                except OSError:
                    pass
                self.create_session(con, cur.lastrowid)
                audit(con, cur.lastrowid, None, "Administrator created")
                self.redirect("/")
                return
            if path == "/login":
                email, password = fields.get("email", "").strip(), fields.get("password", "")
                row = con.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
                if not row or not row["active"] or not hmac.compare_digest(row["password_hash"], hash_password(password, bytes.fromhex(row["password_hash"].split("$")[0]))):
                    self.page("Log in", self.login_form() + '<p class="error">Sign-in failed. Check your email, password, and account status.</p>', status=401)
                    return
                self.create_session(con, row["id"])
                destination = fields.get("next", "/")
                destination_url = urlparse(destination)
                allowed_paths = {"/", "/tasks/new", "/profile", "/audit", "/admin/users", "/trash"}
                safe_destination = destination_url.path if not destination_url.netloc and (destination_url.path in allowed_paths or re.fullmatch(r"/tasks/\d+", destination_url.path)) else "/"
                self.redirect(safe_destination)
                return
            if path == "/register":
                name, email, password = fields.get("name", "").strip(), fields.get("email", "").strip(), fields.get("password", "")
                error = self.validate_user(name, email, password)
                if not fields.get("consent"):
                    error = "You must agree to the processing of test data."
                if error:
                    self.page("Registration", self.register_form() + f'<p class="error">{esc(error)}</p>', status=400)
                    return
                try:
                    cur = con.execute("INSERT INTO users(name,email,password_hash,role,consent,created_at) VALUES(?,?,?,?,1,?)", (name, email, hash_password(password), "member", now()))
                except sqlite3.IntegrityError:
                    self.page("Registration", self.register_form() + '<p class="error">This email is already registered.</p>', status=409)
                    return
                audit(con, cur.lastrowid, None, "Registration")
                self.redirect("/login?message=" + quote("Registration complete. Please sign in."))
                return
            if path == "/password/reset":
                email = fields.get("email", "").strip()
                row = con.execute("SELECT id FROM users WHERE email=? COLLATE NOCASE AND active=1", (email,)).fetchone()
                if not valid_email(email):
                    self.page("Password reset", self.reset_request_form() + '<p class="error">Enter a valid email address.</p>', status=400)
                    return
                if row:
                    token = secrets.token_urlsafe(32)
                    con.execute("INSERT INTO reset_tokens(token,user_id,expires_at) VALUES(?,?,?)", (token, row["id"], int(time.time()) + 1800))
                    link = f'/password/reset/confirm?token={quote(token)}'
                    fd = os.open(RESET_OUTBOX_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                    with os.fdopen(fd, "a", encoding="utf-8") as outbox:
                        outbox.write(f'{now()} {row["id"]} {link}\n')
                self.page("Password reset", '<p class="notice">If an active account with that email exists, a reset link will be sent.</p>')
                return
            if path == "/password/reset/confirm":
                token, password = fields.get("token", ""), fields.get("password", "")
                row = con.execute("SELECT * FROM reset_tokens WHERE token=? AND used=0 AND expires_at>=?", (token, int(time.time()))).fetchone()
                if not row or row["used"] or row["expires_at"] < int(time.time()):
                    self.page("Password reset", '<p class="error">This link is invalid or has expired.</p>', status=400)
                    return
                if not valid_password(password):
                    self.page("New password", self.reset_confirm_form(token) + '<p class="error">Password must contain at least 8 characters, including a letter and a number.</p>', status=400)
                    return
                claimed = con.execute("UPDATE reset_tokens SET used=1 WHERE token=? AND used=0 AND expires_at>=?", (token, int(time.time())))
                if claimed.rowcount != 1:
                    self.page("Password reset", '<p class="error">This link is invalid or has expired.</p>', status=400)
                    return
                con.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), row["user_id"]))
                con.execute("DELETE FROM reset_tokens WHERE user_id=?", (row["user_id"],))
                con.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
                audit(con, row["user_id"], None, "Password reset")
                self.redirect("/login?message=" + quote("Password changed. Please sign in with your new password."))
                return
            if path == "/logout":
                if not self.require_csrf(user, fields):
                    self.error(user, "This form has expired. Refresh the page and try again.", 403)
                    return
                if user:
                    con.execute("DELETE FROM sessions WHERE token=?", (user["token"],))
                self.redirect("/login?message=" + quote("You have signed out."))
                return
            if not user:
                self.redirect("/login")
                return
            if not self.require_csrf(user, fields):
                self.error(user, "This form has expired. Refresh the page and try again.", 403)
                return
            if path == "/tasks/create":
                if user["role"] == "guest":
                    self.error(user, "Guests cannot create tasks.", 403)
                    return
                error = self.validate_task(con, fields)
                if error:
                    self.page("New task", self.task_form(con, user) + f'<p class="error">{esc(error)}</p>', status=400)
                    return
                cur = con.execute("INSERT INTO tasks(title,description,deadline,status,tags,owner_id,assignee_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (fields["title"].strip(), fields.get("description", "").strip(), fields.get("deadline", ""), fields.get("status", "To Do"), json.dumps(tags_from_text(fields.get("tags", "")), ensure_ascii=False), user["id"], self.assignee(con, fields.get("assignee_id")), now(), now()))
                audit(con, user["id"], cur.lastrowid, "Task created")
                self.redirect(f'/tasks/{cur.lastrowid}')
                return
            if path.startswith("/tasks/"):
                parts = path.strip("/").split("/")
                if len(parts) not in (3, 5) or not parts[1].isdigit():
                    self.error(user, "Page not found.", 404)
                    return
                task_id, action = int(parts[1]), parts[2]
                task = self.task_by_id(con, task_id, include_deleted=(action == "restore"))
                if not task:
                    self.error(user, "Task not found.", 404)
                    return
                if len(parts) == 5 and parts[2] == "comments" and parts[3].isdigit():
                    comment = con.execute("SELECT * FROM comments WHERE id=? AND task_id=?", (int(parts[3]), task_id)).fetchone()
                    if not comment:
                        self.error(user, "Comment not found.", 404)
                        return
                    if user["role"] != "admin" and user["id"] != comment["user_id"]:
                        self.error(user, "You can only edit or delete your own comments.", 403)
                        return
                    if parts[4] == "edit":
                        body = fields.get("body", "").strip()
                        if not body or len(body) > 2000:
                            self.error(user, "Comments must contain between 1 and 2,000 characters.")
                            return
                        con.execute("UPDATE comments SET body=? WHERE id=?", (body, comment["id"]))
                        audit(con, user["id"], task_id, "Comment edited")
                    elif parts[4] == "delete":
                        con.execute("DELETE FROM comments WHERE id=?", (comment["id"],))
                        audit(con, user["id"], task_id, "Comment deleted")
                    else:
                        self.error(user, "Page not found.", 404)
                        return
                    self.redirect(f"/tasks/{task_id}")
                    return
                if action == "edit":
                    if not self.can_manage(user, task):
                        self.error(user, "Only the task owner or an administrator can edit this task.", 403)
                        return
                    error = self.validate_task(con, fields)
                    if error:
                        self.page("Edit task", self.task_form(con, user, task) + f'<p class="error">{esc(error)}</p>', status=400)
                        return
                    requested_status = fields.get("status", task["status"])
                    if user["role"] != "admin" and task["assignee_id"] != user["id"]:
                        requested_status = task["status"]
                    con.execute("UPDATE tasks SET title=?,description=?,deadline=?,status=?,tags=?,assignee_id=?,updated_at=? WHERE id=?", (fields["title"].strip(), fields.get("description", "").strip(), fields.get("deadline", ""), requested_status, json.dumps(tags_from_text(fields.get("tags", "")), ensure_ascii=False), self.assignee(con, fields.get("assignee_id")), now(), task_id))
                    audit(con, user["id"], task_id, "Task updated")
                    self.redirect(f"/tasks/{task_id}")
                    return
                if action == "autosave":
                    if not self.can_manage(user, task):
                        self.json_response(403, {"error": "permission_denied"})
                        return
                    error = self.validate_task(con, fields)
                    if error:
                        self.json_response(400, {"error": error})
                        return
                    requested_status = fields.get("status", task["status"])
                    if user["role"] != "admin" and task["assignee_id"] != user["id"]:
                        requested_status = task["status"]
                    con.execute("UPDATE tasks SET title=?,description=?,deadline=?,status=?,tags=?,assignee_id=?,updated_at=? WHERE id=?", (fields["title"].strip(), fields.get("description", "").strip(), fields.get("deadline", ""), requested_status, json.dumps(tags_from_text(fields.get("tags", "")), ensure_ascii=False), self.assignee(con, fields.get("assignee_id")), now(), task_id))
                    audit(con, user["id"], task_id, "Autosave")
                    self.json_response(200, {"saved": True})
                    return
                if action == "status":
                    if user["role"] == "guest" or (user["role"] != "admin" and task["assignee_id"] != user["id"]):
                        self.error(user, "Only the assigned user or an administrator can change the status.", 403)
                        return
                    new_status = fields.get("status", "")
                    if new_status not in STATUSES:
                        self.error(user, "Unknown status. Select a value from the list.")
                        return
                    con.execute("UPDATE tasks SET status=?,updated_at=? WHERE id=?", (new_status, now(), task_id))
                    audit(con, user["id"], task_id, "Status changed", f'{task["status"]} -> {new_status}')
                    self.redirect(f"/tasks/{task_id}")
                    return
                if action == "delete":
                    if not self.can_manage(user, task):
                        self.error(user, "Only the task owner or an administrator can delete this task.", 403)
                        return
                    con.execute("UPDATE tasks SET deleted_at=?,updated_at=? WHERE id=?", (now(), now(), task_id))
                    audit(con, user["id"], task_id, "Task deleted")
                    self.redirect("/?message=" + quote("Task moved to trash."))
                    return
                if action == "restore":
                    if user["role"] != "admin" or not task["deleted_at"]:
                        self.error(user, "Only an administrator can restore this task.", 403)
                        return
                    con.execute("UPDATE tasks SET deleted_at=NULL,updated_at=? WHERE id=?", (now(), task_id))
                    audit(con, user["id"], task_id, "Task restored")
                    self.redirect(f"/tasks/{task_id}")
                    return
                if action == "comments":
                    allowed = user["role"] == "admin" or (user["role"] == "member" and user["id"] in (task["owner_id"], task["assignee_id"]))
                    body = fields.get("body", "").strip()
                    if not allowed:
                        self.error(user, "Only members of this task can comment.", 403)
                        return
                    if not body:
                        self.error(user, "Comments cannot be empty.")
                        return
                    con.execute("INSERT INTO comments(task_id,user_id,body,created_at) VALUES(?,?,?,?)", (task_id, user["id"], body[:2000], now()))
                    audit(con, user["id"], task_id, "Comment added")
                    self.redirect(f"/tasks/{task_id}")
                    return
            if path.startswith("/admin/users/"):
                if user["role"] != "admin":
                    self.error(user, "Only an administrator can perform this action.", 403)
                    return
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[2].isdigit():
                    target_id, action = int(parts[2]), parts[3]
                    target = con.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
                    if not target:
                        self.error(user, "User not found.", 404)
                    elif action == "toggle":
                        new_active = 0 if target["active"] else 1
                        if not new_active and target["role"] == "admin" and con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] <= 1:
                            self.error(user, "You cannot deactivate the last active administrator.", 409)
                            return
                        con.execute("UPDATE users SET active=? WHERE id=?", (new_active, target_id))
                        if not new_active:
                            con.execute("DELETE FROM sessions WHERE user_id=?", (target_id,))
                        audit(con, user["id"], None, "User status changed", f'{target["email"]}: {"active" if new_active else "inactive"}')
                        self.redirect("/admin/users")
                    elif action == "role":
                        new_role = fields.get("role", "")
                        is_last_admin = target["role"] == "admin" and new_role != "admin" and con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] <= 1
                        if new_role not in ROLES or target_id == user["id"] and new_role != "admin" or is_last_admin:
                            self.error(user, "Invalid role.")
                        else:
                            con.execute("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
                            audit(con, user["id"], None, "Role changed", f'{target["email"]}: {new_role}')
                            self.redirect("/admin/users")
                    return
            self.error(user, "Page not found.", 404)

    def validate_user(self, name, email, password):
        if not name or len(name) > 80:
            return "Enter a name of up to 80 characters."
        if not valid_email(email):
            return "Enter a valid email address."
        if not valid_password(password):
            return "Password must contain at least 8 characters, including a letter and a number."
        return ""

    def assignee(self, con, value):
        if not value:
            return None
        try:
            user_id = int(value)
        except ValueError:
            return None
        row = con.execute("SELECT id FROM users WHERE id=? AND active=1 AND role!='guest'", (user_id,)).fetchone()
        return row["id"] if row else None

    def validate_task(self, con, fields):
        title = fields.get("title", "").strip()
        if not title:
            return "A task title is required."
        if len(title) > 160:
            return "The title cannot exceed 160 characters."
        deadline = fields.get("deadline", "").strip()
        if deadline:
            try:
                dt.date.fromisoformat(deadline)
            except ValueError:
                return "Enter a valid due date."
        if fields.get("status", "To Do") not in STATUSES:
            return "Select a status from the list."
        tags_text = fields.get("tags", "")
        if tags_text.strip() and any(not part.strip() for part in tags_text.split(",")):
            return "Tag names cannot be empty."
        return ""

    def create_session(self, con, user_id):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        con.execute("INSERT INTO sessions(token,user_id,csrf,created_at) VALUES(?,?,?,?)", (token, user_id, csrf, int(time.time())))
        self._new_cookie = token
        original_send = self.send
        def send_with_cookie(status, body, headers=None):
            headers = list(headers or []) + [("Set-Cookie", f"lab7_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800")]
            return original_send(status, body, headers)
        self.send = send_with_cookie


def serve():
    initialize()
    logging.info("Starting lab7 task board on %s:%s", HOST, PORT)
    ThreadingHTTPServer((HOST, PORT), App).serve_forever()


if __name__ == "__main__":
    serve()
