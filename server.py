"""
server.py — Flask wrapper for the security scanner.

Routes:
  GET  /                  → index.html
  POST /run-scan          → JSON body {url, mode, preset, token, cookie, username, password}
                            Runs scanner.py, returns merged markdown report
  GET  /scan-status       → last 30 log lines (poll while scanning)
  GET  /reports           → list saved report files

  --- User Management (Admin API) ---
  GET  /admin/users       → list all users (requires admin-token header)
  POST /admin/users       → add a user  {email, password, role}
  DELETE /admin/users/<email> → remove a user
  POST /admin/verify      → verify login credentials {email, password}
                            returns {ok, role} or 401
"""

from flask import Flask, jsonify, send_from_directory, request
import subprocess, os, glob, time, threading, json, hashlib, secrets

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

app = Flask(__name__, static_folder=BASE_DIR)

_scan_log  = []
_scan_lock = threading.Lock()

# ── User store helpers ────────────────────────────────────────────────────────

def _hash_pw(password: str) -> str:
    """SHA-256 hash of the password (hex string).  Good enough for a local tool;
    use bcrypt for production."""
    return hashlib.sha256(password.encode()).hexdigest()

def _load_users() -> dict:
    """Return {email_lower: {email, pw_hash, role}} dict."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def _ensure_default_admin() -> None:
    """Create a default admin account if the user store is empty."""
    users = _load_users()
    if not any(u.get("role") == "admin" for u in users.values()):
        users["admin@aegis.local"] = {
            "email":   "admin@aegis.local",
            "pw_hash": _hash_pw("Admin@1234"),
            "role":    "admin",
        }
        _save_users(users)

# ── Admin token (random per-process secret; shown once on startup) ────────────
_ADMIN_TOKEN = secrets.token_hex(24)   # used to protect /admin/* endpoints


def _stream_pipe(pipe, label=""):
    """Read lines from a pipe and append to _scan_log."""
    for line in iter(pipe.readline, ""):
        stripped = line.rstrip()
        if stripped:
            entry = f"[{label}] {stripped}" if label else stripped
            with _scan_lock:
                _scan_log.append(entry)
                if len(_scan_log) > 300:
                    _scan_log.pop(0)
    pipe.close()


def _require_admin(req):
    """Return True if the request carries the correct admin token."""
    return req.headers.get("X-Admin-Token") == _ADMIN_TOKEN


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/admin")
def admin_page():
    return send_from_directory(BASE_DIR, "admin.html")


# ── Auth & User-management routes ─────────────────────────────────────────────

@app.route("/admin/verify", methods=["POST"])
def verify_login():
    """Called by the sign-in form.  Returns {ok, role} or 401."""
    body  = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    pw    = body.get("password", "")
    users = _load_users()
    user  = users.get(email)
    if not user or user["pw_hash"] != _hash_pw(pw):
        return jsonify({"ok": False, "error": "Invalid email or password."}), 401
    return jsonify({"ok": True, "role": user.get("role", "user"), "email": user["email"]})


@app.route("/admin/token")
def get_admin_token():
    """Return the per-process admin token so the browser can call /admin/users.
    Only the admin account (verified by the /admin/verify step) should reach
    this endpoint — the front-end guards access.  For a local tool this is
    acceptable; harden further in production."""
    return jsonify({"token": _ADMIN_TOKEN})


@app.route("/admin/users", methods=["GET"])
def list_users():
    if not _require_admin(request):
        return jsonify({"error": "Forbidden"}), 403
    users = _load_users()
    safe  = [{"email": u["email"], "role": u.get("role", "user")} for u in users.values()]
    return jsonify({"users": safe})


@app.route("/admin/users", methods=["POST"])
def add_user():
    if not _require_admin(request):
        return jsonify({"error": "Forbidden"}), 403
    body  = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    pw    = body.get("password", "")
    role  = body.get("role", "user")
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email."}), 400
    if len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400
    if role not in ("admin", "user"):
        role = "user"
    users = _load_users()
    if email in users:
        return jsonify({"error": "Email already exists."}), 409
    users[email] = {"email": email, "pw_hash": _hash_pw(pw), "role": role}
    _save_users(users)
    return jsonify({"ok": True, "email": email, "role": role}), 201


@app.route("/admin/users/<path:email>", methods=["DELETE"])
def delete_user(email):
    if not _require_admin(request):
        return jsonify({"error": "Forbidden"}), 403
    email = email.strip().lower()
    users = _load_users()
    if email not in users:
        return jsonify({"error": "User not found."}), 404
    # Prevent deleting the last admin
    if users[email].get("role") == "admin":
        admins = [u for u in users.values() if u.get("role") == "admin"]
        if len(admins) <= 1:
            return jsonify({"error": "Cannot delete the last admin account."}), 400
    del users[email]
    _save_users(users)
    return jsonify({"ok": True})


@app.route("/admin/users/<path:email>", methods=["PATCH"])
def update_user(email):
    """Update email, password and/or role for an existing user."""
    if not _require_admin(request):
        return jsonify({"error": "Forbidden"}), 403
    email = email.strip().lower()
    users = _load_users()
    if email not in users:
        return jsonify({"error": "User not found."}), 404
    body = request.get_json(force=True, silent=True) or {}

    # Update password
    if "password" in body and body["password"]:
        if len(body["password"]) < 6:
            return jsonify({"error": "Password must be at least 6 characters."}), 400
        users[email]["pw_hash"] = _hash_pw(body["password"])

    # Update role
    if "role" in body and body["role"] in ("admin", "user"):
        if users[email].get("role") == "admin" and body["role"] != "admin":
            admins = [u for u in users.values() if u.get("role") == "admin"]
            if len(admins) <= 1:
                return jsonify({"error": "Cannot demote the last admin account."}), 400
        users[email]["role"] = body["role"]

    # Update email (rename key)
    new_email = (body.get("new_email") or "").strip().lower()
    if new_email and new_email != email:
        if "@" not in new_email:
            return jsonify({"error": "Invalid new email address."}), 400
        if new_email in users:
            return jsonify({"error": "That email is already in use."}), 409
        users[new_email] = users.pop(email)
        users[new_email]["email"] = new_email

    _save_users(users)
    return jsonify({"ok": True})


@app.route("/run-scan", methods=["POST"])
def run_scan():
    body = request.get_json(force=True, silent=True) or {}

    target_url = (body.get("url") or "").strip()
    mode       = body.get("mode", "standard")          # "standard" | "deep"
    preset     = body.get("preset", "")                # known preset name, or ""
    token      = body.get("token", "")
    cookie     = body.get("cookie", "")
    username   = body.get("username", "")
    password   = body.get("password", "")

    if not target_url:
        return jsonify({"error": "No target URL provided."}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400
    if mode not in ("standard", "deep"):
        mode = "standard"

    with _scan_lock:
        _scan_log.clear()

    scan_start = time.time()

    cmd = [
        "python", os.path.join(BASE_DIR, "scanner.py"),
        "--url",  target_url,
        "--mode", mode,
    ]
    # Only add preset if it's a non-empty string
    if preset and preset.strip():
        cmd.extend(["--preset", preset.strip()])
    if token and token.strip():
        cmd.extend(["--token", token.strip()])
    if cookie and cookie.strip():
        cmd.extend(["--cookie-str", cookie.strip()])
    if username and username.strip():
        cmd.extend(["--username", username.strip()])
    if password:
        cmd.extend(["--password", password])

    # Log the command being run (without password) for debugging
    safe_cmd = [c for c in cmd if c != password]
    with _scan_lock:
        _scan_log.append(f"[*] Running: {' '.join(safe_cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=BASE_DIR,
        )

        # Stream BOTH stdout and stderr into the log concurrently.
        # Using proc.communicate() after starting threads that read
        # proc.stdout causes a deadlock / empty reads — we use
        # proc.wait() instead and let the threads drain the pipes.
        stdout_thread = threading.Thread(
            target=_stream_pipe, args=(proc.stdout, ""), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_stream_pipe, args=(proc.stderr, "ERR"), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        timeout = 1800 if mode == "deep" else 900   # 30 min deep / 15 min standard
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return jsonify({"error": f"Scan timed out after {timeout//60} minutes."}), 504

        # Wait for both pipe-reader threads to finish
        stdout_thread.join(timeout=10)
        stderr_thread.join(timeout=10)

        with _scan_lock:
            all_log = list(_scan_log)

        # Collect stderr lines from the log for the response
        stderr_lines = [l[len("[ERR] "):] for l in all_log if l.startswith("[ERR] ")]
        stderr_text  = "\n".join(stderr_lines)
        stdout_text  = "\n".join(l for l in all_log if not l.startswith("[ERR] "))

        reports = [
            f for f in glob.glob(os.path.join(BASE_DIR, "reports", "*.md"))
            if os.path.getmtime(f) >= scan_start - 2
        ]
        reports.sort(key=os.path.getmtime)

        if proc.returncode != 0 and not reports:
            return jsonify({
                "error":  "Scanner exited with errors and produced no report.",
                "stderr": stderr_text,
                "stdout": stdout_text,
            }), 500

        if not reports:
            return jsonify({
                "error":  "Scan finished but no report was generated.",
                "stderr": stderr_text,
                "stdout": stdout_text,
            }), 500

        sections = []
        for path in reports:
            with open(path, encoding="utf-8") as f:
                sections.append(f.read())
        merged = "\n\n---\n\n".join(sections)

        return jsonify({
            "report_files": reports,
            "report_file":  reports[-1],
            "markdown":     merged,
            "stdout":       stdout_text,
            "stderr":       stderr_text,
            "returncode":   proc.returncode,
        })

    except FileNotFoundError:
        return jsonify({"error": "scanner.py not found in the same directory as server.py."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan-status")
def scan_status():
    with _scan_lock:
        lines = list(_scan_log[-30:])
    return jsonify({"lines": lines})


@app.route("/reports")
def list_reports():
    files = sorted(
        glob.glob(os.path.join(BASE_DIR, "reports", "*.md")),
        key=os.path.getmtime, reverse=True,
    )
    return jsonify({"reports": files})


if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    _ensure_default_admin()
    print("=" * 60)
    print("  AEGIS Security Assessment Platform")
    print("  App   : http://localhost:5000")
    print("  Admin : http://localhost:5000/admin")
    print()
    print("  Default admin login:")
    print("    Email   : admin@aegis.local")
    print("    Password: Admin@1234")
    print("=" * 60)
    app.run(port=5000, debug=False)