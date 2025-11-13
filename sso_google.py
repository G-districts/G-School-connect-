"""
sso_google.py
Google OAuth 2.0 Authentication Blueprint for Flask
Restricts sign-in to @gdistrict.org accounts.
"""

from flask import Blueprint, redirect, request, session, jsonify
from google_auth_oauthlib.flow import Flow
from urllib.parse import urljoin
import requests
import os

# ==============================
# Blueprint
# ==============================
sso_google_bp = Blueprint("sso_google_bp", __name__, url_prefix="/auth/google")

# Allow local HTTP for testing (disable in production)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# ==============================
# OAuth Config
# ==============================
CLIENT_CONFIG = {
    "web": {
        "client_id": "97200938621-spp9cqldkttgmtsmaun38tkpq8te36ah.apps.googleusercontent.com",
        "project_id": "summer-bond-472005-g3",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "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",
        "redirect_uris": [
            "http://localhost:5000/auth/google/callback",
            "https://gschool.gdistrict.org/auth/google/callback"
        ]
    }
}

# ==============================
# Helpers
# ==============================

def make_flow():
    """Create a new OAuth Flow instance for each request."""
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )
    # Dynamically set correct redirect based on environment
    if "localhost" in request.host or "127.0.0.1" in request.host:
        flow.redirect_uri = "http://localhost:5000/auth/google/callback"
    else:
        flow.redirect_uri = "https://gschool.gdistrict.org/auth/google/callback"
    return flow


def get_base_url():
    """Detect current base URL for redirects."""
    if "localhost" in request.host or "127.0.0.1" in request.host:
        return "http://localhost:5000"
    return f"https://{request.host}"


# ==============================
# Routes
# ==============================

@sso_google_bp.route("/login")
def google_login():
    """Start Google OAuth login."""
    flow = make_flow()
    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
    )
    session["state"] = state
    return redirect(auth_url)


@sso_google_bp.route("/callback")
def google_callback():
    """Handle OAuth callback from Google."""
    try:
        flow = make_flow()
        flow.fetch_token(authorization_response=request.url)

        # Get user info
        credentials = flow.credentials
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {credentials.token}"},
        )
        user = resp.json()
        email = user.get("email", "")
        name = user.get("name", "")

        # Restrict to @gdistrict.org
        if not email.endswith("@gdistrict.org"):
            return redirect(urljoin(get_base_url(), "/unauthorized"))

        # Store session
        session["user"] = {
            "email": email,
            "name": name,
            "picture": user.get("picture", ""),
            "domain": email.split("@")[-1],
            "role": "teacher"
        }

        # ✅ Redirect properly depending on environment
        redirect_url = urljoin(get_base_url(), "/teacher")
        return redirect(redirect_url)

    except Exception as e:
        print("[OAuth Error]", e)
        return jsonify({
            "error": "OAuth callback failed",
            "details": str(e),
            "hint": "Ensure redirect URI matches exactly in Google Cloud Console."
        }), 500


@sso_google_bp.route("/logout")
def google_logout():
    session.clear()
    return redirect(urljoin(get_base_url(), "/"))


@sso_google_bp.route("/whoami")
def google_whoami():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401
    return jsonify(session["user"])
