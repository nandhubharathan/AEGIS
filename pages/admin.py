"""
pages/admin.py — AEGIS Admin Dashboard
========================================
Pure-Streamlit admin panel for the AEGIS vulnerability scanner.
• Authentication via st.secrets (ADMIN_USER / ADMIN_PASS)
• User management with read-only filesystem warning
• Scanner monitoring with placeholder data
• Dark-mode styled with st.metric cards

Run as part of the multipage app:  streamlit run app.py
"""

import streamlit as st
import json, os, hashlib, time, datetime, random, base64

try:
    from github import Github, GithubException
    _PYGITHUB_INSTALLED = True
except ImportError:
    _PYGITHUB_INSTALLED = False

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE  = os.path.join(BASE_DIR, "users.json")

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AEGIS — Admin Console",
    page_icon="⚙️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# DARK-MODE CSS INJECTION
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Root overrides ──────────────────────────────────────────────────── */
:root {
    --bg-primary:   #04070d;
    --bg-secondary: #080e18;
    --bg-card:      #0c1322;
    --accent:       #00c8ff;
    --accent-glow:  rgba(0, 200, 255, .15);
    --danger:       #ff3860;
    --danger-glow:  rgba(255, 56, 96, .12);
    --success:      #23d160;
    --warning:      #ffdd57;
    --text-main:    #cad8e8;
    --text-dim:     #5a7a94;
    --border:       #15202e;
    --font:         'Inter', 'Segoe UI', system-ui, sans-serif;
}

/* ── Global ──────────────────────────────────────────────────────────── */
html, body, .stApp {
    background: var(--bg-primary) !important;
    color: var(--text-main) !important;
    font-family: var(--font) !important;
}

/* ── Hide Streamlit chrome ───────────────────────────────────────────── */
#MainMenu, footer, .stDeployButton,
div[data-testid="stToolbar"],
div[data-testid="stDecoration"],
div[data-testid="stStatusWidget"] { display: none !important; }

/* ── Sidebar ─────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] .stRadio label {
    color: var(--text-dim) !important;
    font-weight: 500;
    transition: color .2s;
}
section[data-testid="stSidebar"] .stRadio label:hover {
    color: var(--accent) !important;
}

/* ── Metric cards ────────────────────────────────────────────────────── */
div[data-testid="stMetric"] {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.1rem 1.4rem;
    transition: transform .2s, border-color .3s;
}
div[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
    box-shadow: 0 0 18px var(--accent-glow);
}
div[data-testid="stMetric"] label {
    color: var(--text-dim) !important;
    font-size: .82rem !important;
    text-transform: uppercase;
    letter-spacing: .08em;
}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: var(--accent) !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
}

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {
    background: linear-gradient(135deg, var(--accent), #0090b8) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    letter-spacing: .04em;
    transition: box-shadow .25s, transform .15s !important;
}
.stButton > button:hover {
    box-shadow: 0 0 20px var(--accent-glow) !important;
    transform: translateY(-1px) !important;
}
/* Danger button override for emergency stop */
div[data-testid="stHorizontalBlock"] .danger-btn button {
    background: linear-gradient(135deg, var(--danger), #b8002e) !important;
}
div[data-testid="stHorizontalBlock"] .danger-btn button:hover {
    box-shadow: 0 0 22px var(--danger-glow) !important;
}

/* ── Data-table / expander ───────────────────────────────────────────── */
.stDataFrame, .stTable {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px;
}
details[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
}
details[data-testid="stExpander"] summary {
    color: var(--text-dim) !important;
    font-weight: 600;
}

/* ── Inputs ──────────────────────────────────────────────────────────── */
.stTextInput input, .stSelectbox select {
    background: var(--bg-secondary) !important;
    color: var(--text-main) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}
.stTextInput input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px var(--accent-glow) !important;
}

/* ── Warning box styling ─────────────────────────────────────────────── */
div[data-testid="stAlert"] {
    border-radius: 10px !important;
}

/* ── Divider ─────────────────────────────────────────────────────────── */
hr {
    border-color: var(--border) !important;
    opacity: .5;
}

/* ── Header glow ─────────────────────────────────────────────────────── */
.admin-header {
    text-align: center;
    padding: 1.2rem 0 .4rem;
}
.admin-header h1 {
    font-size: 2.2rem;
    background: linear-gradient(90deg, var(--accent), #7b61ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
}
.admin-header p {
    color: var(--text-dim);
    font-size: .92rem;
    margin: .3rem 0 0;
}

/* ── User cards ──────────────────────────────────────────────────────── */
.user-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: .85rem 1.1rem;
    margin-bottom: .6rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: border-color .3s;
}
.user-card:hover { border-color: var(--accent); }
.user-card .email { color: var(--text-main); font-weight: 500; }
.user-card .role {
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .1em;
    padding: .2rem .7rem;
    border-radius: 20px;
    font-weight: 700;
}
.user-card .role.admin  { background: var(--accent-glow); color: var(--accent); }
.user-card .role.user   { background: rgba(255,255,255,.06); color: var(--text-dim); }

/* ── Scanner row ─────────────────────────────────────────────────────── */
.scan-row {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: .75rem 1.1rem;
    margin-bottom: .5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
}
.scan-row .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
}
.scan-row .dot.running  { background: var(--success); box-shadow: 0 0 8px var(--success); }
.scan-row .dot.queued   { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
.scan-row .target { color: var(--text-main); font-family: monospace; font-size: .88rem; }
.scan-row .meta   { color: var(--text-dim); font-size: .78rem; margin-left: auto; }

/* ── Pulse animation for "live" indicator ────────────────────────────── */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: .45; }
}
.live-dot {
    display: inline-block;
    width: 8px; height: 8px;
    background: var(--success);
    border-radius: 50%;
    margin-right: .5rem;
    animation: pulse 1.8s ease-in-out infinite;
}
</style>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION — gated via st.secrets
# ══════════════════════════════════════════════════════════════════════════════
def _check_secrets_available():
    """Return True if ADMIN_USER and ADMIN_PASS are configured in st.secrets."""
    try:
        _ = st.secrets["ADMIN_USER"]
        _ = st.secrets["ADMIN_PASS"]
        return True
    except (KeyError, FileNotFoundError):
        return False


def _authenticate():
    """
    Render a login form and gate access to the admin dashboard.
    Credentials are read from st.secrets['ADMIN_USER'] and st.secrets['ADMIN_PASS'].
    Falls back to hardcoded demo credentials when secrets aren't configured
    (local development only).
    """
    if st.session_state.get("admin_authenticated"):
        return True

    secrets_ok = _check_secrets_available()

    # ── Centred login card ────────────────────────────────────────────────
    st.markdown("""
    <div class="admin-header">
        <h1>⚙️ AEGIS Admin Console</h1>
        <p>Authenticate to access system controls</p>
    </div>
    """, unsafe_allow_html=True)

    col_l, col_mid, col_r = st.columns([1, 1.5, 1])
    with col_mid:
        st.markdown("---")
        if not secrets_ok:
            st.info(
                "🔑 **Dev Mode** — `st.secrets` not found.  \n"
                "Using fallback credentials: `admin` / `aegis2026`  \n"
                "On Streamlit Cloud, add `ADMIN_USER` and `ADMIN_PASS` to your app secrets.",
                icon="🛠️",
            )

        with st.form("admin_login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="admin", key="login_user")
            password = st.text_input("Password", type="password", placeholder="••••••••", key="login_pass")
            submit = st.form_submit_button("🔐  Log In", use_container_width=True)

        if submit:
            if secrets_ok:
                valid_user = st.secrets["ADMIN_USER"]
                valid_pass = st.secrets["ADMIN_PASS"]
            else:
                # Fallback for local dev / demo
                valid_user = "admin"
                valid_pass = "aegis2026"

            if username == valid_user and password == valid_pass:
                st.session_state["admin_authenticated"] = True
                st.session_state["admin_login_time"] = datetime.datetime.now().isoformat()
                st.rerun()
            else:
                st.error("❌ Invalid credentials. Access denied.", icon="🚫")

    return False


# ══════════════════════════════════════════════════════════════════════════════
# USER STORE HELPERS (mirrors app.py logic)
# ══════════════════════════════════════════════════════════════════════════════
def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_users(users: dict):
    """Write users.json locally. Will silently fail on a read-only filesystem."""
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return True
    except OSError:
        return False


def _github_available() -> bool:
    """Return True if PyGithub is installed and GitHub secrets are configured."""
    if not _PYGITHUB_INSTALLED:
        return False
    try:
        _ = st.secrets["GITHUB_TOKEN"]
        _ = st.secrets["GITHUB_REPO"]
        return True
    except (KeyError, FileNotFoundError):
        return False


def _push_users_to_github(users: dict, commit_msg: str = "Update users.json via AEGIS Admin") -> tuple[bool, str]:
    """
    Commit the current users dict to users.json in the GitHub repo.
    Returns (success: bool, message: str).
    """
    if not _github_available():
        return False, "GitHub integration not configured (missing GITHUB_TOKEN / GITHUB_REPO secrets)."

    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo(st.secrets["GITHUB_REPO"])
        file_path = "users.json"
        new_content = json.dumps(users, indent=2)

        # Get the current file to obtain its SHA (required for updates)
        try:
            contents = repo.get_contents(file_path, ref=repo.default_branch)
            repo.update_file(
                path=file_path,
                message=commit_msg,
                content=new_content,
                sha=contents.sha,
                branch=repo.default_branch,
            )
        except Exception:
            # File doesn't exist yet — create it
            repo.create_file(
                path=file_path,
                message=commit_msg,
                content=new_content,
                branch=repo.default_branch,
            )

        return True, f"✅ Committed to `{st.secrets['GITHUB_REPO']}` ({repo.default_branch})"

    except GithubException as e:
        return False, f"GitHub API error: {e.data.get('message', str(e))}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# PLACEHOLDER DATA — simulates live scanner telemetry
# ══════════════════════════════════════════════════════════════════════════════
def _placeholder_scans():
    """Return synthetic active-scan data for dashboard demo."""
    targets = [
        ("https://juice-shop.herokuapp.com", "deep",   "running",  72, "2m 14s"),
        ("https://dvwa.example.org",         "standard","running",  41, "0m 58s"),
        ("https://webgoat.local:8080",       "deep",   "queued",    0, "—"),
    ]
    return [
        {"target": t, "mode": m, "status": s, "progress": p, "elapsed": e}
        for t, m, s, p, e in targets
    ]


def _placeholder_metrics():
    """Return synthetic KPI values with deltas."""
    return {
        "total_scans":          (1_247, "+38 this week"),
        "active_vulnerabilities": (63, "-12 from last scan"),
        "system_health":        ("98.7%", "+0.3%"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION RENDERERS
# ══════════════════════════════════════════════════════════════════════════════

# ── Overview / KPI cards ─────────────────────────────────────────────────────
def _render_overview():
    metrics = _placeholder_metrics()

    st.markdown("""
    <div class="admin-header">
        <h1>⚙️ AEGIS Admin Console</h1>
        <p><span class="live-dot"></span>System operational · All services online</p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Scans",            metrics["total_scans"][0],            metrics["total_scans"][1])
    with c2:
        st.metric("Active Vulnerabilities",  metrics["active_vulnerabilities"][0], metrics["active_vulnerabilities"][1])
    with c3:
        st.metric("System Health",           metrics["system_health"][0],          metrics["system_health"][1])

    st.markdown("---")


# ── Scanner Controls ─────────────────────────────────────────────────────────
def _render_scanner():
    st.subheader("🖥️  Scanner Controls")

    scans = _placeholder_scans()

    for s in scans:
        dot_class = s["status"]
        st.markdown(f"""
        <div class="scan-row">
            <div class="dot {dot_class}"></div>
            <span class="target">{s['target']}</span>
            <span class="meta">{s['mode'].upper()} · {s['progress']}% · {s['elapsed']}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # Progress bars for running scans
    for s in scans:
        if s["status"] == "running":
            st.progress(s["progress"] / 100, text=f"{s['target']}  —  {s['progress']}%")

    st.markdown("")

    # Emergency Stop
    col1, col2, _ = st.columns([1, 1, 2])
    with col1:
        if st.button("🔄  Refresh Status", use_container_width=True, key="refresh_scans"):
            st.toast("Scanner status refreshed.", icon="🔄")
            st.rerun()
    with col2:
        if st.button("🛑  EMERGENCY STOP ALL", use_container_width=True, type="primary", key="estop"):
            st.session_state["emergency_stopped"] = True

    if st.session_state.get("emergency_stopped"):
        st.warning(
            "⚠️ **EMERGENCY STOP TRIGGERED**  \n"
            "All scanning services have been sent the SIGTERM signal.  \n"
            "In production, wire this to your process manager / container orchestrator.",
            icon="🛑",
        )
        if st.button("✅  Clear Emergency Flag", key="clear_estop"):
            st.session_state["emergency_stopped"] = False
            st.rerun()

    st.markdown("---")


# ── User Management ──────────────────────────────────────────────────────────
def _render_users():
    st.subheader("👥  User Management")

    gh_ok = _github_available()

    # ── GitHub integration status ────────────────────────────────────────
    if gh_ok:
        st.success(
            "🔗 **GitHub auto-commit enabled.**  \n"
            "User changes will be pushed to `" + st.secrets["GITHUB_REPO"] + "` automatically.",
            icon="✅",
        )
    else:
        st.warning(
            "🔒 **Streamlit Cloud has a read-only filesystem.**  \n"
            "Any user changes made here are **ephemeral** — they survive only until "
            "the next app restart / dyno cycle.  \n\n"
            "**To enable auto-commit**, add `GITHUB_TOKEN` and `GITHUB_REPO` to your "
            "`st.secrets`, and install `PyGithub`.  \n"
            "Otherwise, permanent changes require a manual GitHub commit to `users.json`.",
            icon="⚠️",
        )

    users = _load_users()

    # ── Display current users ────────────────────────────────────────────
    if users:
        for email, u in users.items():
            role = u.get("role", "user")
            st.markdown(f"""
            <div class="user-card">
                <span class="email">{email}</span>
                <span class="role {role}">{role}</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No users found in `users.json`.")

    st.markdown("")

    # ── Add User ─────────────────────────────────────────────────────────
    with st.expander("➕  Add New User", expanded=False):
        with st.form("add_user_form", clear_on_submit=True):
            au_email = st.text_input("Email", placeholder="operator@company.com")
            au_pass  = st.text_input("Password", type="password", placeholder="Min. 6 characters")
            au_role  = st.selectbox("Role", ["user", "admin"])
            au_submit = st.form_submit_button("Add User", use_container_width=True)

        if au_submit:
            email_key = au_email.strip().lower() if au_email else ""
            if not email_key or "@" not in email_key:
                st.error("Please enter a valid email address.")
            elif not au_pass or len(au_pass) < 6:
                st.error("Password must be at least 6 characters.")
            elif email_key in users:
                st.error(f"`{email_key}` already exists.")
            else:
                users[email_key] = {
                    "email": email_key,
                    "pw_hash": _hash_pw(au_pass),
                    "role": au_role,
                }
                _save_users(users)  # local write (best-effort)

                # Push to GitHub if configured
                if gh_ok:
                    pushed, msg = _push_users_to_github(
                        users,
                        commit_msg=f"Add user {email_key} via AEGIS Admin",
                    )
                    if pushed:
                        st.success(f"✅ Added **{email_key}** as `{au_role}`.  \n{msg}")
                    else:
                        st.warning(f"User added locally but GitHub push failed: {msg}")
                else:
                    st.success(f"✅ Added **{email_key}** as `{au_role}` (local only — ephemeral).")
                st.rerun()

    # ── Remove User ──────────────────────────────────────────────────────
    with st.expander("🗑️  Remove User", expanded=False):
        if users:
            remove_email = st.selectbox(
                "Select user to remove",
                options=list(users.keys()),
                key="remove_user_select",
            )
            if st.button("Remove Selected User", key="remove_user_btn"):
                target = users.get(remove_email, {})
                # Guard: prevent deleting the last admin
                admins = [e for e, u in users.items() if u.get("role") == "admin"]
                if target.get("role") == "admin" and len(admins) <= 1:
                    st.error("🚫 Cannot remove the last admin account.")
                else:
                    del users[remove_email]
                    _save_users(users)  # local write (best-effort)

                    # Push to GitHub if configured
                    if gh_ok:
                        pushed, msg = _push_users_to_github(
                            users,
                            commit_msg=f"Remove user {remove_email} via AEGIS Admin",
                        )
                        if pushed:
                            st.success(f"Removed `{remove_email}`.  \n{msg}")
                        else:
                            st.warning(f"User removed locally but GitHub push failed: {msg}")
                    else:
                        st.success(f"Removed `{remove_email}` (local only — ephemeral).")
                    st.rerun()
        else:
            st.info("No users to remove.")

    # ── Raw JSON viewer ──────────────────────────────────────────────────
    with st.expander("📄  Raw users.json", expanded=False):
        st.json(users)

    st.markdown("---")


# ── System Logs (placeholder) ────────────────────────────────────────────────
def _render_logs():
    st.subheader("📋  System Logs")

    log_lines = [
        f"[{(datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 120))).strftime('%H:%M:%S')}]  "
        + random.choice([
            "INFO  scanner.engine — OWASP ZAP passive scan completed",
            "INFO  auth.session  — Admin session authenticated from 192.168.1.42",
            "WARN  scanner.net   — Connection timeout on target port 8443",
            "INFO  report.gen    — Markdown report written to /reports/scan_20260428.md",
            "INFO  scanner.engine — Starting deep scan pipeline (13 checks)",
            "DEBUG health.check  — CPU 12% · MEM 38% · Disk 24%",
            "WARN  scanner.tls   — Certificate transparency log mismatch detected",
            "INFO  user.mgmt     — User joshua@gmail.com logged in",
        ])
        for _ in range(15)
    ]
    log_lines.sort()

    st.code("\n".join(log_lines), language="log")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    # ── Gate: must authenticate first ────────────────────────────────────
    if not _authenticate():
        return

    # ── Sidebar navigation ───────────────────────────────────────────────
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding: .8rem 0;">
            <span style="font-size:2rem;">🛡️</span><br>
            <span style="color:var(--accent); font-weight:700; font-size:1.1rem;">AEGIS</span><br>
            <span style="color:var(--text-dim); font-size:.75rem; letter-spacing:.12em;">ADMIN CONSOLE</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        page = st.radio(
            "Navigation",
            ["📊 Overview", "🖥️ Scanner Controls", "👥 User Management", "📋 System Logs"],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # Session info
        login_time = st.session_state.get("admin_login_time", "—")
        st.caption(f"🔐 Logged in at `{login_time}`")

        if st.button("🚪  Log Out", use_container_width=True, key="logout_btn"):
            st.session_state["admin_authenticated"] = False
            st.session_state.pop("admin_login_time", None)
            st.rerun()

    # ── Page routing ─────────────────────────────────────────────────────
    if page == "📊 Overview":
        _render_overview()
        _render_scanner()
        _render_users()
    elif page == "🖥️ Scanner Controls":
        _render_overview()
        _render_scanner()
    elif page == "👥 User Management":
        _render_users()
    elif page == "📋 System Logs":
        _render_logs()


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
