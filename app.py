"""
app.py — AEGIS Security Assessment Platform (Streamlit Edition)
================================================================
Embeds the original index.html UI pixel-perfectly inside Streamlit,
with the backend powered by Python/Streamlit instead of Flask.

Run:  streamlit run app.py
"""

import streamlit as st
import streamlit.components.v1 as components
import subprocess, os, sys, json, hashlib, glob, re, time, datetime, threading, io

# ── Shared user data layer ───────────────────────────────────────────────────
from user_store import load_users, save_users, hash_pw, ensure_admin, invalidate_cache

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
USERS_FILE  = os.path.join(BASE_DIR, "users.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AEGIS — Security Assessment Platform",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ══════════════════════════════════════════════════════════════════════════════
# HIDE STREAMLIT CHROME — we want ONLY our UI visible
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
#MainMenu, footer, header, .stDeployButton,
div[data-testid="stToolbar"],
div[data-testid="stDecoration"],
div[data-testid="stStatusWidget"] { display:none !important; }
.stApp { background: #04070d !important; }
section[data-testid="stSidebar"] { display:none !important; }
.block-container { padding:0 !important; max-width:100% !important; }
div[data-testid="stAppViewBlockContainer"] { padding:0 !important; }
iframe { border:none !important; }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# USER STORE — powered by shared user_store.py
# ══════════════════════════════════════════════════════════════════════════════
ensure_admin()

# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════
for k, v in {"user":None, "scan_phase":"idle", "scan_log":[], "scan_result":None, "scan_report_md":""}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ══════════════════════════════════════════════════════════════════════════════
# SCAN EXECUTION (runs scanner.py OWASP checks via direct import)
# ══════════════════════════════════════════════════════════════════════════════
def run_scan_internal(target_url, mode, preset, token, cookie, username, password):
    """Run scanner.py as subprocess and capture output + report."""
    cmd = [sys.executable, os.path.join(BASE_DIR, "scanner.py"),
           "--url", target_url, "--mode", mode]
    if preset:   cmd += ["--preset", preset]
    if token:    cmd += ["--token", token]
    if cookie:   cmd += ["--cookie-str", cookie]
    if username: cmd += ["--username", username]
    if password: cmd += ["--password", password]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR, timeout=1800)
        raw_stdout = proc.stdout or ""
        lines = [l for l in raw_stdout.split('\n') if l.strip()]
    except subprocess.TimeoutExpired:
        lines = ["[!] Scan timed out after 30 minutes"]
        raw_stdout = ""
    except FileNotFoundError:
        lines = ["[!] scanner.py not found"]
        raw_stdout = ""
    except Exception as e:
        lines = [f"[!] Error: {e}"]
        raw_stdout = ""

    # Extract report markdown from stdout (between delimiters)
    md = ""
    if "===AEGIS_REPORT_START===" in raw_stdout and "===AEGIS_REPORT_END===" in raw_stdout:
        md = raw_stdout.split("===AEGIS_REPORT_START===", 1)[1].split("===AEGIS_REPORT_END===", 1)[0].strip()

    # Fallback: try to find report file on disk (works locally)
    if not md:
        start_t = time.time()
        reports = sorted(
            [f for f in glob.glob(os.path.join(REPORTS_DIR, "*.md"))
             if os.path.getmtime(f) >= start_t - 30],
            key=os.path.getmtime
        )
        if reports:
            with open(reports[-1], encoding="utf-8") as f:
                md = f.read()

    # Filter out the report delimiters from the log lines shown to the user
    lines = [l for l in lines if "===AEGIS_REPORT" not in l and not l.startswith("# Security Assessment")]

    return lines, md

# ══════════════════════════════════════════════════════════════════════════════
# API-LIKE HANDLER — processes requests from the embedded HTML
# ══════════════════════════════════════════════════════════════════════════════
# Since we can't have fetch() calls from the iframe to a Flask server,
# we use Streamlit query params + form submissions to handle communication.
# The approach: render the full original HTML with JS modified to use
# Streamlit's postMessage bridge for key actions.

# ══════════════════════════════════════════════════════════════════════════════
# BUILD THE FULL HTML PAGE
# ══════════════════════════════════════════════════════════════════════════════
def build_full_html():
    """Read index.html and modify JS to work standalone (no Flask backend)."""

    # Read the original HTML
    html_path = os.path.join(BASE_DIR, "index.html")
    with open(html_path, encoding="utf-8") as f:
        original_html = f.read()

    # Get users for client-side auth (reads from shared store)
    users = load_users()
    users_json = json.dumps({
        email: {"email": u["email"], "pw_hash": u["pw_hash"], "role": u.get("role","user")}
        for email, u in users.items()
    })

    # Get existing reports for display
    reports_list = []
    for rp in sorted(glob.glob(os.path.join(REPORTS_DIR, "*.md")), key=os.path.getmtime, reverse=True)[:10]:
        try:
            with open(rp, encoding="utf-8") as f:
                reports_list.append({"name": os.path.basename(rp), "content": f.read()})
        except:
            pass
    reports_json = json.dumps(reports_list)

    # Inject our custom JS BEFORE the closing </script> to override fetch-based functions
    override_js = f"""
// ═══════════════════════════════════════════════════
// STREAMLIT OVERRIDES — replace Flask API calls
// ═══════════════════════════════════════════════════
const _USERS_DB = {users_json};
const _REPORTS_DB = {reports_json};

// SHA-256 hash function (browser native)
async function sha256(msg) {{
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}}

// Override signIn to work client-side
async function signIn() {{
    const email = document.getElementById('si-email').value.trim().toLowerCase();
    const pass  = document.getElementById('si-pass').value;
    const err   = document.getElementById('si-err');
    document.getElementById('si-email').classList.remove('err');
    document.getElementById('si-pass').classList.remove('err');
    err.textContent = '';

    if(!email || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){{
        document.getElementById('si-email').classList.add('err');
        err.textContent = 'Please enter a valid email address.'; return;
    }}
    if(!pass || pass.length < 1){{
        document.getElementById('si-pass').classList.add('err');
        err.textContent = 'Please enter your password.'; return;
    }}

    err.textContent = 'Authenticating…';
    const hash = await sha256(pass);
    const user = _USERS_DB[email];

    if(!user || user.pw_hash !== hash){{
        err.textContent = 'Invalid email or password.';
        document.getElementById('si-email').classList.add('err');
        document.getElementById('si-pass').classList.add('err');
        return;
    }}

    _currentUser = {{email: user.email, role: user.role}};
    if(user.role === 'admin') _adminToken = 'streamlit-admin';
    _afterLogin();
}}

// Override admin functions for client-side operation
async function adminLoadUsers(){{
    if(!_adminToken) return;
    const tbody = document.getElementById('utbl-body');
    const users = Object.values(_USERS_DB);
    if(!users.length){{ tbody.innerHTML='<tr><td colspan="3" class="utbl-empty">No users found.</td></tr>'; return; }}
    tbody.innerHTML = users.map(u=>`
        <tr>
            <td>${{eh(u.email)}}</td>
            <td><span class="role-badge ${{u.role}}">${{u.role.toUpperCase()}}</span></td>
            <td style="text-align:right">
                <button class="btn-role" onclick="adminToggleRole('${{eh(u.email)}}','${{u.role==='admin'?'user':'admin'}}')"
                    title="Toggle role">${{u.role==='admin'?'→ USER':'→ ADMIN'}}</button>
                <button class="btn-del" onclick="adminDeleteUser('${{eh(u.email)}}')" title="Remove user">✕ REMOVE</button>
            </td>
        </tr>`).join('');
}}

async function adminAddUser(){{
    const email = document.getElementById('au-email').value.trim().toLowerCase();
    const pass  = document.getElementById('au-pass').value;
    const role  = document.getElementById('au-role').value;
    _setAuMsg('','');
    if(!email || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){{ _setAuMsg('Invalid email address.','err'); return; }}
    if(!pass || pass.length < 6){{ _setAuMsg('Password must be at least 6 characters.','err'); return; }}
    if(_USERS_DB[email]){{ _setAuMsg('User already exists.','err'); return; }}

    const hash = await sha256(pass);
    _USERS_DB[email] = {{email: email, pw_hash: hash, role: role}};

    // Send to Streamlit to persist
    window.parent.postMessage({{type:'aegis_add_user', email:email, pw_hash:hash, role:role}}, '*');

    _setAuMsg(`✓ User ${{email}} added successfully.`,'ok');
    document.getElementById('au-email').value='';
    document.getElementById('au-pass').value='';
    document.getElementById('au-role').value='user';
    adminLoadUsers();
}}

async function adminDeleteUser(email){{
    if(!confirm(`Remove user "${{email}}"? This cannot be undone.`)) return;
    const admins = Object.values(_USERS_DB).filter(u=>u.role==='admin');
    if(_USERS_DB[email] && _USERS_DB[email].role==='admin' && admins.length<=1){{
        alert('Cannot delete the last admin.'); return;
    }}
    delete _USERS_DB[email];
    window.parent.postMessage({{type:'aegis_delete_user', email:email}}, '*');
    adminLoadUsers();
}}

async function adminToggleRole(email, newRole){{
    if(!confirm(`Change role of "${{email}}" to ${{newRole}}?`)) return;
    if(_USERS_DB[email].role==='admin'){{
        const admins = Object.values(_USERS_DB).filter(u=>u.role==='admin');
        if(admins.length<=1){{ alert('Cannot demote the last admin.'); return; }}
    }}
    _USERS_DB[email].role = newRole;
    window.parent.postMessage({{type:'aegis_toggle_role', email:email, role:newRole}}, '*');
    adminLoadUsers();
}}

// Override launch() to use Streamlit postMessage
async function launch(){{
    const raw = document.getElementById('urlInput').value.trim();
    const uel = document.getElementById('urlInput');
    if(!raw){{uel.classList.add('err');return;}}
    if(!/^https?:\\/\\//i.test(raw)){{uel.classList.add('err');showErr('URL must start with http:// or https://');return;}}
    uel.classList.remove('err');
    document.getElementById('errbox').style.display='none';
    const st = document.getElementById('status');
    setScanningUI(true);
    st.className=`sline run${{_mode==='deep'?' dp':''}}`;
    st.textContent=_mode==='deep'?`Deep scanning ${{raw}}…`:`Scanning ${{raw}}…`;
    startLog();
    startProgressBar();

    // Send scan request to Streamlit
    window.parent.postMessage({{
        type: 'aegis_run_scan',
        url: raw,
        mode: _mode,
        preset: _preset,
        token: document.getElementById('authToken').value.trim(),
        cookie: document.getElementById('authCookie').value.trim(),
        username: document.getElementById('authUser').value.trim(),
        password: document.getElementById('authPass').value
    }}, '*');

    // Poll for results via postMessage
    _scanPollInterval = setInterval(()=>{{
        window.parent.postMessage({{type:'aegis_poll_scan'}}, '*');
    }}, 2000);
}}

let _scanPollInterval = null;

// Listen for messages from Streamlit
window.addEventListener('message', function(event) {{
    const d = event.data;
    if(!d || !d.type) return;

    if(d.type === 'aegis_scan_status') {{
        // Update log
        if(d.lines && d.lines.length > _logAll.length) {{
            const fresh = d.lines.slice(_logAll.length);
            _logAll.push(...fresh);
            rebuildFilt();
            const pages = Math.max(1, Math.ceil(_logFilt.length/LPS));
            _logPg = pages;
            renderLog();
        }}
    }}

    if(d.type === 'aegis_scan_complete') {{
        clearInterval(_scanPollInterval);
        _scanPollInterval = null;

        const st = document.getElementById('status');
        if(d.error) {{
            st.className='sline err';
            st.textContent='✗ Scan failed';
            stopProgressBar(false);
            showErr('Error: ' + d.error);
        }} else {{
            st.className='sline done';
            st.textContent='✓ Scan complete';
            stopProgressBar(true);

            if(d.markdown) {{
                // VirusTotal if enabled
                let vtData = null;
                if(_vtEnabled){{
                    const apiKey = VT_API_KEY.trim();
                    if(apiKey && apiKey !== 'PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE'){{
                        (async()=>{{
                            try{{ vtData = await runVirusTotal(d.url, apiKey); }}catch(e){{}}
                            buildReport({{markdown: d.markdown}}, d.url, d.mode, vtData);
                        }})();
                    }} else {{
                        buildReport({{markdown: d.markdown}}, d.url, d.mode, null);
                    }}
                }} else {{
                    buildReport({{markdown: d.markdown}}, d.url, d.mode, null);
                }}
            }}
        }}
        setScanningUI(false);
        stopLog();
    }}

    if(d.type === 'aegis_scan_log_update') {{
        if(d.lines) {{
            _logAll.push(...d.lines);
            rebuildFilt();
            const pages = Math.max(1, Math.ceil(_logFilt.length/LPS));
            _logPg = pages;
            renderLog();
        }}
    }}
}});

// Override: Load an existing report if available
function loadLastReport() {{
    if(_REPORTS_DB.length > 0) {{
        const rpt = _REPORTS_DB[0];
        buildReport({{markdown: rpt.content}}, '(previous scan)', 'standard', null);
    }}
}}
"""

    # Insert our override JS right BEFORE the closing </script>
    # We need to remove the original signIn, adminLoadUsers, adminAddUser,
    # adminDeleteUser, adminToggleRole, and launch functions, then add ours
    # Strategy: inject our code at the END of the script, overwriting the functions

    modified_html = original_html.replace(
        '</script>',
        override_js + '\n</script>'
    )

    return modified_html


# ══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ══════════════════════════════════════════════════════════════════════════════
def main():
    # Handle incoming messages from the iframe via query params
    # (Streamlit can't receive postMessage directly, so we use a workaround)

    # For scan requests, we use a separate mechanism:
    # The iframe posts a message, and we poll via a hidden component

    # Read the full HTML
    html_content = build_full_html()

    # Render the original HTML as a full-page component
    components.html(
        html_content,
        height=900,
        scrolling=True,
    )

    # ── Scan execution sidebar (hidden by CSS) ────────────────────────────
    # We use the sidebar for scan controls since the iframe can't
    # directly trigger Python code. Instead, users can also trigger scans
    # from this panel.

    with st.sidebar:
        st.markdown("### 🛡 AEGIS Scanner")
        st.markdown("---")

        scan_url = st.text_input("Target URL", placeholder="https://target.example.com")
        scan_mode = st.radio("Mode", ["standard", "deep"])
        scan_preset = st.selectbox("Preset", ["(none)", "juice_shop", "dvwa", "webgoat"])

        with st.expander("Authentication"):
            s_token = st.text_input("Bearer Token", key="s_token")
            s_cookie = st.text_input("Cookie", key="s_cookie")
            s_user = st.text_input("Username", key="s_user")
            s_pass = st.text_input("Password", type="password", key="s_pass")

        if st.button("▶ LAUNCH SCAN", use_container_width=True):
            if not scan_url:
                st.error("Enter a target URL")
            elif not scan_url.startswith(("http://", "https://")):
                st.error("URL must start with http:// or https://")
            else:
                preset = scan_preset if scan_preset != "(none)" else ""
                with st.status(f"Scanning {scan_url}...", expanded=True) as status:
                    progress = st.progress(0, text="Initializing...")
                    log_area = st.empty()

                    progress.progress(10, text="Running scanner...")
                    lines, md = run_scan_internal(
                        scan_url, scan_mode, preset,
                        s_token, s_cookie, s_user, s_pass
                    )
                    progress.progress(100, text="Complete!")

                    st.session_state.scan_log = lines
                    st.session_state.scan_report_md = md

                    if lines:
                        log_area.code('\n'.join(lines[-20:]))

                    if md:
                        status.update(label="✓ Scan complete!", state="complete")
                        st.success(f"Report saved! Found in reports/ directory.")
                    else:
                        status.update(label="Scan finished — check results", state="complete")

        # Show last report
        if st.session_state.scan_report_md:
            st.markdown("---")
            st.markdown("### Latest Report")
            with st.expander("View Report Markdown"):
                st.code(st.session_state.scan_report_md[:3000], language="markdown")

        # Admin section
        st.markdown("---")
        st.markdown("### 👤 User Management")
        users = load_users()
        for email, u in users.items():
            col1, col2 = st.columns([3,1])
            with col1:
                st.text(f"{u['email']} ({u.get('role','user')})")

        with st.expander("Add User"):
            new_email = st.text_input("Email", key="new_email")
            new_pass = st.text_input("Password", type="password", key="new_pass")
            new_role = st.selectbox("Role", ["user", "admin"], key="new_role")
            if st.button("Add User"):
                if new_email and new_pass and len(new_pass) >= 6:
                    users = load_users()
                    email_key = new_email.strip().lower()
                    if email_key not in users:
                        users[email_key] = {
                            "email": email_key,
                            "pw_hash": hash_pw(new_pass),
                            "role": new_role
                        }
                        save_users(users, commit_msg=f"Add user {email_key} via main page")
                        st.success(f"Added {email_key}")
                        st.rerun()
                    else:
                        st.error("Email already exists")

if __name__ == "__main__":
    main()
