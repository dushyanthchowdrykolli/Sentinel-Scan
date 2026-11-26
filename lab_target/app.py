"""
lab_target/app.py

Intentionally vulnerable Flask application for demonstrating Sentinel Scan.

Vulnerabilities present:
  - Reflected XSS on /xss (name parameter echoed without encoding)
  - SQL injection error on /sqli (id parameter interpolated into query string)
  - Missing security headers (no CSP, HSTS, X-Frame-Options, etc.)
  - Weak cookie flags (session cookie without Secure, HttpOnly, SameSite)
  - Server banner disclosure (Flask default X-Powered-By-ish via Server header)
  - No CSRF token on the login form

Run with:
    python lab_target/app.py

The app listens on http://127.0.0.1:5000
"""

import sqlite3
import tempfile
import os

from flask import Flask, make_response, request, redirect, url_for

app = Flask(__name__)

# ----------------------------------------------------------------------------
# In-memory SQLite database for the SQLi demo
# ----------------------------------------------------------------------------
_db_path = os.path.join(tempfile.gettempdir(), "sentinel_lab_demo.db")

def _init_demo_db():
    conn = sqlite3.connect(_db_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT
        )"""
    )
    conn.execute("DELETE FROM users")  # Reset on each start
    conn.executemany(
        "INSERT INTO users (username, email) VALUES (?, ?)",
        [
            ("alice", "alice@example.com"),
            ("bob", "bob@example.com"),
            ("admin", "admin@example.com"),
        ],
    )
    conn.commit()
    conn.close()

_init_demo_db()


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

PAGE_WRAPPER = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Lab Target — {title}</title>
  <style>
    body {{
      font-family: system-ui, sans-serif;
      max-width: 760px;
      margin: 40px auto;
      padding: 0 20px;
      color: #222;
    }}
    h1 {{ color: #b91c1c; }}
    h2 {{ color: #374151; }}
    nav a {{ margin-right: 16px; color: #1d4ed8; text-decoration: none; }}
    nav a:hover {{ text-decoration: underline; }}
    .warning {{ background: #fef3c7; border: 1px solid #fcd34d;
                padding: 10px 14px; border-radius: 4px; margin-bottom: 16px;
                font-size: .875rem; }}
    pre {{ background: #f3f4f6; padding: 12px; border-radius: 4px;
           font-size: .875rem; white-space: pre-wrap; }}
    input[type=text], input[type=password] {{
      padding: 7px 10px; border: 1px solid #d1d5db;
      border-radius: 4px; font-size: 1rem; width: 260px;
    }}
    button {{ padding: 7px 20px; background: #1d4ed8; color: #fff;
              border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }}
  </style>
</head>
<body>
  <div class="warning">
    This is an intentionally vulnerable application for security testing demos only.
    Do not expose it to any network.
  </div>
  <nav>
    <a href="/">Home</a>
    <a href="/xss">XSS Demo</a>
    <a href="/sqli">SQLi Demo</a>
    <a href="/login">Login (no CSRF)</a>
    <a href="/robots.txt">robots.txt</a>
  </nav>
  <hr style="margin: 16px 0">
  {content}
</body>
</html>"""


def render(title, content):
    resp = make_response(PAGE_WRAPPER.format(title=title, content=content))

    # Deliberately omit security headers
    # (Sentinel Scan should detect their absence)

    # Weak cookie: missing Secure, HttpOnly, SameSite
    resp.set_cookie(
        "lab_session",
        "demo-session-token-12345",
        # No secure=True, no httponly=True, no samesite
    )

    # Disclose server technology via header
    resp.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.11"
    resp.headers["Server"] = "Werkzeug/3.0.1 Python/3.11"

    return resp


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------

@app.route("/")
def index():
    content = """
    <h1>Sentinel Scan Lab Target</h1>
    <p>This Flask application contains deliberate vulnerabilities:</p>
    <ul style="line-height:2">
      <li><a href="/xss?name=World">Reflected XSS</a> — input echoed without escaping</li>
      <li><a href="/sqli?id=1">SQL Injection</a> — id parameter used in raw SQL</li>
      <li><a href="/login">Login form</a> — POST form without CSRF token</li>
      <li>Missing security headers on every response</li>
      <li>Cookies set without Secure / HttpOnly / SameSite flags</li>
      <li>Server banner disclosure via X-Powered-By and Server headers</li>
    </ul>
    """
    return render("Home", content)


@app.route("/xss")
def xss():
    """
    Reflected XSS: the 'name' query parameter is echoed directly into the
    HTML response without any output encoding.
    """
    name = request.args.get("name", "")
    # VULNERABILITY: direct interpolation into HTML — do not fix
    content = f"""
    <h2>XSS Demo</h2>
    <p>Hello, {name}!</p>
    <form method="GET" action="/xss">
      <input type="text" name="name" value="{name}" placeholder="Enter your name">
      <button type="submit">Submit</button>
    </form>
    <p style="font-size:.875rem;color:#6b7280;margin-top:12px">
      The 'name' parameter is reflected without HTML encoding.
    </p>
    """
    return render("XSS Demo", content)


@app.route("/sqli")
def sqli():
    """
    SQL injection: the 'id' parameter is interpolated directly into the
    SQL query string using Python string formatting.
    """
    user_id = request.args.get("id", "1")

    result_html = ""
    error_html = ""

    try:
        conn = sqlite3.connect(_db_path)
        # VULNERABILITY: raw string interpolation into SQL — do not fix
        query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
        rows = conn.execute(query).fetchall()
        conn.close()

        if rows:
            rows_html = "".join(
                f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
                for r in rows
            )
            result_html = f"""
            <table border="1" cellpadding="6" style="border-collapse:collapse;margin-top:8px">
              <tr><th>ID</th><th>Username</th><th>Email</th></tr>
              {rows_html}
            </table>
            """
        else:
            result_html = "<p>No results found.</p>"
    except sqlite3.OperationalError as exc:
        # VULNERABILITY: raw error message exposed to user — do not fix
        error_html = f"""
        <pre style="color:#b91c1c">SQLite3 OperationalError: {exc}

Query: {query}</pre>
        """

    content = f"""
    <h2>SQL Injection Demo</h2>
    <form method="GET" action="/sqli">
      <input type="text" name="id" value="{user_id}" placeholder="User ID">
      <button type="submit">Look up</button>
    </form>
    <p style="font-size:.875rem;color:#6b7280;margin-top:8px">
      Try: id=1, id=1 OR 1=1, id=1'
    </p>
    {error_html}
    {result_html}
    """
    return render("SQLi Demo", content)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login form without a CSRF token.
    POST simply echoes the submitted username.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        content = f"""
        <h2>Logged in as: {username}</h2>
        <p><a href="/login">Back to login</a></p>
        """
        return render("Login", content)

    content = """
    <h2>Login</h2>
    <p style="font-size:.875rem;color:#6b7280">
      This form uses POST but has no CSRF token hidden field.
    </p>
    <form method="POST" action="/login">
      <div style="margin-bottom:10px">
        <input type="text" name="username" placeholder="Username" required>
      </div>
      <div style="margin-bottom:10px">
        <input type="password" name="password" placeholder="Password">
      </div>
      <button type="submit">Log in</button>
    </form>
    """
    return render("Login", content)


@app.route("/robots.txt")
def robots():
    """
    robots.txt that reveals internal paths.
    """
    content = "User-agent: *\nDisallow: /admin\nDisallow: /internal/\nDisallow: /backup\n"
    resp = make_response(content, 200)
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/admin")
def admin():
    """Simulated admin panel — returns 200 to trigger the exposed-paths finding."""
    content = """
    <h2>Admin Panel</h2>
    <p>This admin page is publicly accessible (no authentication required).</p>
    """
    return render("Admin", content)


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  Sentinel Scan Lab Target")
    print("  http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
