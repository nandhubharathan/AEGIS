"""
app.py - AEGIS Security Assessment Platform (Streamlit Edition)
================================================================
Embeds the original index.html UI inside Streamlit,
with the backend powered by Python/Streamlit instead of Flask.

Run:  streamlit run app.py
"""

import streamlit as st
import streamlit.components.v1 as components
import subprocess, os, sys, json, hashlib, re

# -- Shared user data layer
from user_store import load_users, save_users, hash_pw, ensure_admin, invalidate_cache

# -- Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -- Page config
st.set_page_config(
    page_title="AEGIS - Security Assessment Platform",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Hide Streamlit chrome
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

ensure_admin()

# Session state
for k, v in {"user":None, "scan_phase":"idle", "scan_log":[], "scan_result":None, "scan_report_md":""}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ==============================================================================
# SCAN EXECUTION
# ==============================================================================
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

    md = ""
    if "===AEGIS_REPORT_START===" in raw_stdout and "===AEGIS_REPORT_END===" in raw_stdout:
        md = raw_stdout.split("===AEGIS_REPORT_START===", 1)[1].split("===AEGIS_REPORT_END===", 1)[0].strip()

    lines = [l for l in lines if "===AEGIS_REPORT" not in l and not l.startswith("# Security Assessment")]
    return lines, md

# ==============================================================================
# BUILD THE FULL HTML PAGE
# ==============================================================================
def build_full_html():
    """Read index.html and modify JS to work standalone (no Flask backend)."""

    html_path = os.path.join(BASE_DIR, "index.html")
    with open(html_path, encoding="utf-8") as f:
        original_html = f.read()

    users = load_users(force_refresh=True)
    users_json = json.dumps({
        email: {"email": u["email"], "pw_hash": u["pw_hash"], "role": u.get("role","user")}
        for email, u in users.items()
    })

    scan_result = st.session_state.get("scan_result") or {}
    scan_result_json = json.dumps(scan_result)

    # Build override JS as plain string with placeholders (avoids f-string escape hell)
    override_js = """
// STREAMLIT OVERRIDES
const _USERS_DB = __USERS__;
const _REPORTS_DB = [];

async function sha256(msg) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function signIn() {
    var email = document.getElementById('si-email').value.trim().toLowerCase();
    var pass  = document.getElementById('si-pass').value;
    var err   = document.getElementById('si-err');
    document.getElementById('si-email').classList.remove('err');
    document.getElementById('si-pass').classList.remove('err');
    err.textContent = '';
    if(!email || email.indexOf('@') < 1 || email.indexOf('.') < 3){
        document.getElementById('si-email').classList.add('err');
        err.textContent = 'Please enter a valid email address.'; return;
    }
    if(!pass || pass.length < 1){
        document.getElementById('si-pass').classList.add('err');
        err.textContent = 'Please enter your password.'; return;
    }
    err.textContent = 'Authenticating...';
    var hash = await sha256(pass);
    var user = _USERS_DB[email];
    if(!user || user.pw_hash !== hash){
        err.textContent = 'Invalid email or password.';
        document.getElementById('si-email').classList.add('err');
        document.getElementById('si-pass').classList.add('err');
        return;
    }
    _currentUser = {email: user.email, role: user.role};
    if(user.role === 'admin') _adminToken = 'streamlit-admin';
    _afterLogin();
}

async function adminLoadUsers(){
    if(!_adminToken) return;
    var tbody = document.getElementById('utbl-body');
    var users = Object.values(_USERS_DB);
    if(!users.length){ tbody.innerHTML='<tr><td colspan="3">No users.</td></tr>'; return; }
    tbody.innerHTML = users.map(function(u){
        return '<tr><td>'+eh(u.email)+'</td><td><span class="role-badge '+u.role+'">'+u.role.toUpperCase()+'</span></td><td></td></tr>';
    }).join('');
}
async function adminAddUser(){
    var email = document.getElementById('au-email').value.trim().toLowerCase();
    var pass  = document.getElementById('au-pass').value;
    var role  = document.getElementById('au-role').value;
    _setAuMsg('','');
    if(!email){ _setAuMsg('Enter email.','err'); return; }
    if(!pass || pass.length < 6){ _setAuMsg('Min 6 chars.','err'); return; }
    if(_USERS_DB[email]){ _setAuMsg('Exists.','err'); return; }
    var hash = await sha256(pass);
    _USERS_DB[email] = {email:email, pw_hash:hash, role:role};
    _setAuMsg('Added.','ok');
    document.getElementById('au-email').value='';
    document.getElementById('au-pass').value='';
    adminLoadUsers();
}
async function adminDeleteUser(email){
    if(!confirm('Remove?')) return;
    delete _USERS_DB[email];
    adminLoadUsers();
}
async function adminToggleRole(email, newRole){
    if(_USERS_DB[email]) _USERS_DB[email].role = newRole;
    adminLoadUsers();
}

// SANDBOX ESCAPE: Inject a message listener into the PARENT document.
// This works because Streamlit's iframe has allow-same-origin + allow-scripts.
// st.markdown strips <script> tags, but we can inject directly into parent DOM.
try {
    var _pd = window.parent.document;
    if (!_pd._aegisReady) {
        _pd._aegisReady = true;
        var _sc = _pd.createElement('script');
        _sc.textContent = [
            'window.addEventListener("message", function(e) {',
            '  var d = e.data;',
            '  if (!d || d.type !== "aegis_run_scan") return;',
            '  var p = new URLSearchParams();',
            '  p.set("aegis_scan", "1");',
            '  p.set("scan_url", d.scan_url || "");',
            '  p.set("scan_mode", d.scan_mode || "standard");',
            '  p.set("scan_preset", d.scan_preset || "");',
            '  p.set("scan_token", d.scan_token || "");',
            '  p.set("scan_cookie", d.scan_cookie || "");',
            '  p.set("scan_user", d.scan_user || "");',
            '  p.set("scan_pass", d.scan_pass || "");',
            '  window.location.href = window.location.pathname + "?" + p.toString();',
            '});'
        ].join('\\n');
        _pd.head.appendChild(_sc);
    }
} catch(ex) {
    console.log('Cannot access parent frame:', ex);
}

// SCAN - post message to parent (listener was injected above)
async function launch(){
    var raw = document.getElementById('urlInput').value.trim();
    var uel = document.getElementById('urlInput');
    if(!raw){uel.classList.add('err');return;}
    if(raw.indexOf('http://') !== 0 && raw.indexOf('https://') !== 0){
        uel.classList.add('err');showErr('URL must start with http:// or https://');return;
    }
    uel.classList.remove('err');
    document.getElementById('errbox').style.display='none';
    var stEl = document.getElementById('status');
    setScanningUI(true);
    stEl.className='sline run';
    stEl.textContent='Scanning ' + raw + '...';
    startLog();
    startProgressBar();

    window.parent.postMessage({
        type: 'aegis_run_scan',
        scan_url: raw,
        scan_mode: _mode,
        scan_preset: _preset || '',
        scan_token: document.getElementById('authToken').value.trim(),
        scan_cookie: document.getElementById('authCookie').value.trim(),
        scan_user: document.getElementById('authUser').value.trim(),
        scan_pass: document.getElementById('authPass').value
    }, '*');
}

// Check for scan results injected by Streamlit
var _SCAN_RESULT = __SCAN_RESULT__;
if(_SCAN_RESULT && _SCAN_RESULT.done) {
    document.addEventListener('DOMContentLoaded', function() {
        goPage('p4');
        document.getElementById('logbox').classList.add('show');
        document.getElementById('livebadge').className='livebadge off';
        document.getElementById('livebadge').textContent='DONE';
        if(_SCAN_RESULT.lines) {
            _logAll = _SCAN_RESULT.lines;
            rebuildFilt();
            renderLog();
        }
        var stEl = document.getElementById('status');
        if(_SCAN_RESULT.error && !_SCAN_RESULT.markdown) {
            stEl.className='sline err';
            stEl.textContent='Scan issue: ' + _SCAN_RESULT.error;
        } else {
            stEl.className='sline done';
            stEl.textContent='Scan complete';
        }
        if(_SCAN_RESULT.url) {
            document.getElementById('urlInput').value = _SCAN_RESULT.url;
            try { document.getElementById('sh-co').textContent = _SCAN_RESULT.url; } catch(e) {}
        }
        if(_SCAN_RESULT.markdown) {
            setTimeout(function() {
                buildReport({markdown: _SCAN_RESULT.markdown}, _SCAN_RESULT.url || '', _SCAN_RESULT.mode || 'standard', null);
            }, 300);
        }
    });
}

function loadLastReport() {}
"""

    override_js = override_js.replace("__USERS__", users_json)
    override_js = override_js.replace("__SCAN_RESULT__", scan_result_json)

    modified_html = original_html.replace('</script>', override_js + '\n</script>')
    return modified_html


# ==============================================================================
# MAIN APP
# ==============================================================================
def main():
    # -- Check for scan request via query params
    params = st.query_params
    if params.get("aegis_scan") == "1":
        scan_url = params.get("scan_url", "")
        scan_mode = params.get("scan_mode", "standard")
        scan_preset = params.get("scan_preset", "")
        scan_token = params.get("scan_token", "")
        scan_cookie = params.get("scan_cookie", "")
        scan_user = params.get("scan_user", "")
        scan_pass = params.get("scan_pass", "")

        st.query_params.clear()

        with st.status(f"Scanning {scan_url}...", expanded=True) as status:
            progress = st.progress(0, text="Initializing...")
            log_area = st.empty()
            progress.progress(10, text="Running scanner...")
            lines, md = run_scan_internal(
                scan_url, scan_mode, scan_preset,
                scan_token, scan_cookie, scan_user, scan_pass
            )
            progress.progress(100, text="Complete!")
            if lines:
                log_area.code('\n'.join(lines[-30:]))
            status.update(label="Scan complete!", state="complete")

        st.session_state.scan_result = {
            "done": True,
            "url": scan_url,
            "mode": scan_mode,
            "lines": lines,
            "markdown": md,
            "error": "" if md else "No report generated",
        }
        st.session_state.scan_log = lines
        st.session_state.scan_report_md = md
        st.rerun()

    # -- Render the main page
    html_content = build_full_html()
    components.html(html_content, height=900, scrolling=True)

    # Show report below iframe if available
    if st.session_state.scan_report_md:
        st.markdown("---")
        st.markdown("### Latest Scan Report")
        with st.expander("View Full Report", expanded=False):
            st.markdown(st.session_state.scan_report_md)

    # Clear scan result after rendering
    if st.session_state.get("scan_result"):
        st.session_state.scan_result = None


if __name__ == "__main__":
    main()
