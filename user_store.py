"""
user_store.py — Shared user data layer for AEGIS
==================================================
Single source of truth for user management across all pages.

Priority chain for reading users:
  1. st.session_state["_users_cache"]  (in-session instant sync)
  2. GitHub API via PyGithub            (cross-session real-time sync)
  3. Local users.json file              (fallback / local dev)

Priority chain for writing users:
  1. st.session_state["_users_cache"]  (instant in-session update)
  2. Local users.json file              (best-effort, fails on read-only FS)
  3. GitHub API commit                  (persistent cross-session update)
"""

import streamlit as st
import json, os, hashlib, base64

try:
    from github import Github, GithubException
    _PYGITHUB_INSTALLED = True
except ImportError:
    _PYGITHUB_INSTALLED = False

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def github_available() -> bool:
    """Return True if PyGithub is installed and GitHub secrets are configured."""
    if not _PYGITHUB_INSTALLED:
        return False
    try:
        _ = st.secrets["GITHUB_TOKEN"]
        _ = st.secrets["GITHUB_REPO"]
        return True
    except (KeyError, FileNotFoundError):
        return False


def _read_users_from_github() -> dict | None:
    """
    Fetch users.json directly from the GitHub repo via the API.
    Returns the parsed dict, or None on failure.
    """
    if not github_available():
        return None
    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo(st.secrets["GITHUB_REPO"])
        contents = repo.get_contents("users.json", ref=repo.default_branch)
        raw = base64.b64decode(contents.content).decode("utf-8")
        return json.loads(raw)
    except Exception:
        return None


def _push_users_to_github(
    users: dict,
    commit_msg: str = "Update users.json via AEGIS Admin",
) -> tuple[bool, str]:
    """
    Commit the users dict to users.json in the GitHub repo.
    Returns (success, message).
    """
    if not github_available():
        return False, "GitHub integration not configured."

    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo(st.secrets["GITHUB_REPO"])
        new_content = json.dumps(users, indent=2)

        try:
            contents = repo.get_contents("users.json", ref=repo.default_branch)
            repo.update_file(
                path="users.json",
                message=commit_msg,
                content=new_content,
                sha=contents.sha,
                branch=repo.default_branch,
            )
        except Exception:
            repo.create_file(
                path="users.json",
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
# PUBLIC API — used by both app.py and pages/admin.py
# ══════════════════════════════════════════════════════════════════════════════
def hash_pw(pw: str) -> str:
    """SHA-256 hash a password string."""
    return hashlib.sha256(pw.encode()).hexdigest()


def load_users(force_refresh: bool = False) -> dict:
    """
    Load users from the best available source.

    1. Session-state cache (instant, same session) — skipped if force_refresh
    2. GitHub API          (cross-session, real-time)
    3. Local users.json    (fallback)
    """
    # 1) Session-state cache — immediate for same-session page switches
    if not force_refresh and "_users_cache" in st.session_state and st.session_state["_users_cache"]:
        return st.session_state["_users_cache"]

    # 2) GitHub API — authoritative on Cloud
    if github_available():
        gh_users = _read_users_from_github()
        if gh_users is not None:
            st.session_state["_users_cache"] = gh_users
            return gh_users

    # 3) Local file — fallback for local dev
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, encoding="utf-8") as f:
                users = json.load(f)
            st.session_state["_users_cache"] = users
            return users
        except Exception:
            pass

    return {}


def save_users(
    users: dict,
    commit_msg: str = "Update users.json via AEGIS Admin",
) -> tuple[bool, str]:
    """
    Persist users to all available backends.
    Returns (github_pushed: bool, message: str).
    """
    # 1) Session-state cache — instant propagation across pages
    st.session_state["_users_cache"] = users

    # 2) Local file — best-effort (will fail on read-only FS)
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
    except OSError:
        pass  # expected on Streamlit Cloud

    # 3) GitHub push — persistent
    if github_available():
        return _push_users_to_github(users, commit_msg)

    return False, "Local only — no GitHub secrets configured."


def invalidate_cache():
    """Force the next load_users() call to re-fetch from source."""
    st.session_state.pop("_users_cache", None)


def ensure_admin():
    """Guarantee at least one admin account exists."""
    users = load_users()
    if not any(v.get("role") == "admin" for v in users.values()):
        users["admin@aegis.local"] = {
            "email": "admin@aegis.local",
            "pw_hash": hash_pw("Admin@1234"),
            "role": "admin",
        }
        save_users(users, commit_msg="Ensure default admin account exists")
