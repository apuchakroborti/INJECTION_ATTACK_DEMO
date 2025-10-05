# OR 1=1 --
# (Install dependencies if needed: `pip3 install flask werkzeug`.)

# safe_injection_demo.py
from flask import Flask, request, render_template_string, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = "demo-safe-key"

# Initialize in-memory DB and seed a secure user (username: alice, password: secret)
def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    # store hashed password (secure practice)
    c.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("alice", generate_password_hash("secret"), "user")
    )
    # an admin account
    c.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", generate_password_hash("adminpass"), "admin")
    )
    conn.commit()
    return conn

DB = init_db()

PAGE = """
<!doctype html>
<title>SQL Injection — Safe Educational Demo</title>
<h2>SQL Injection — Safe Educational Demo</h2>
<p>Test credentials: <b>alice / secret</b> (regular user), <b>admin / adminpass</b> (admin)</p>

<h3>Vulnerable-looking Form (SIMULATED)</h3>
<form method="post" action="{{ url_for('vulnerable') }}">
  <label>Username: <input name="username" required></label><br>
  <label>Password: <input name="password" required type="password"></label><br>
  <button type="submit">Submit (vulnerable-looking demo)</button>
</form>
<p><i>Note:</i> This route prints the *constructed* unsafe SQL to the server log and will <b>simulate success</b> if it detects a typical injection payload (e.g. <code>' OR 1=1 --</code>). <b>It does not execute the unsafe SQL.</b></p>

<hr>

<h3>Secure Login (ACTUAL)</h3>
<form method="post" action="{{ url_for('secure') }}">
  <label>Username: <input name="username" required></label><br>
  <label>Password: <input name="password" required type="password"></label><br>
  <button type="submit">Secure Login (parameterized)</button>
</form>

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for m in messages %}
      <li><b>{{m}}</b></li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
"""

# Simple detector for classic injection payloads (educational only)
INJECTION_PATTERNS = [
    re.compile(r"'\s*or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"\"\\s*or\\s+1\\s*=\\s*1", re.IGNORECASE),
    re.compile(r"--"),  # inline comment
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
]

def looks_like_injection(s: str) -> bool:
    if s is None:
        return False
    for p in INJECTION_PATTERNS:
        if p.search(s):
            return True
    return False

@app.route("/", methods=["GET"])
def index():
    return render_template_string(PAGE)

@app.route("/vulnerable", methods=["POST"])
def vulnerable():
    """
    Vulnerable-looking demo route.
    - Builds an unsafe SQL string and logs it.
    - If input contains a known injection pattern, SIMULATE a successful login.
    - Never executes the unsafe SQL against the database.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Construct the unsafe SQL string (DO NOT EXECUTE)
    unsafe_sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}';"
    app.logger.info("=== VULNERABLE-LOOKING DEMO: constructed unsafe SQL (NOT executed) ===")
    app.logger.info(unsafe_sql)
    app.logger.info("===================================================================")

    # If we detect classic injection pattern, simulate success for teaching
    if looks_like_injection(username) or looks_like_injection(password):
        # Simulated behavior: attacker bypasses auth — show as simulated
        flash("SIMULATED: Vulnerable login would SUCCEED with that input (this is simulation only).")
        app.logger.info("SIMULATION: Detected injection payload; simulated successful login (no DB executed).")
        return redirect(url_for("index"))

    # Otherwise, treat as normal: do not execute the unsafe SQL; explain that it would fail in demo.
    flash("Vulnerable demo: unsafe SQL was printed to server log. It was NOT executed. Try the secure login below.")
    return redirect(url_for("index"))

@app.route("/secure", methods=["POST"])
def secure():
    """
    Secure login: parameterized query + password hash check.
    This actually queries the in-memory DB safely.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = DB
    c = conn.cursor()
    # Parameterized query prevents injection
    c.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if row is None:
        flash("Secure login: FAILED (unknown user).")
        return redirect(url_for("index"))
    user_id, user_name, pw_hash, role = row
    if check_password_hash(pw_hash, password):
        # login success
        if role == "admin":
            flash(f"Secure login: SUCCESS — admin panel access allowed (user={user_name}).")
        else:
            flash(f"Secure login: SUCCESS — welcome {user_name}.")
    else:
        flash("Secure login: FAILED (invalid password).")
    return redirect(url_for("index"))

if __name__ == "__main__":
    print("Starting safe demo server on http://127.0.0.1:5000")
    print("Vulnerable-looking form will LOG constructed unsafe SQL to server console and SIMULATE success on injection-like input.")
    print("Secure form uses parameterized queries and hashed passwords; injection attempts will not bypass.")
    app.run(debug=True, threaded=True)

## How to use this safely in a workshop

# 1. Run locally:: python3 secure_demo_injection_attack.py  & open `http://127.0.0.1:5000/`.
# 2. In the vulnerable-looking form:

#   Enter normal credentials (e.g., `alice` / `secret`) — nothing is executed and you’ll be told the unsafe SQL was printed to console.
#   Enter a classic injection payload in username or password, for example:
#      ```
#      ' OR 1=1 --
#      ```
# The server will log the exact unsafe SQL string (so students can see it) and simulate a successful login. Emphasize: this is simulated only — the server did not run the unsafe SQL.

# 3. In the secure form:
#  Try the injection payload again — it will not bypass. Only correct credentials (`alice`/`secret` or `admin`/`adminpass`) succeed.

# 4. Use console logs to highlight:
# How vulnerable code interpolates user input into SQL (danger).
# How parameterized queries keep data and code separate.

# ## Teaching points to emphasize
# Why `SELECT ... WHERE username = '...user input...'` is dangerous.
# How `' OR 1=1 --` changes the logic of the SQL statement.
# The secure form demonstrates:

# Parameterized queries (`?`) treat user input as data — injection fails.
# Passwords should be hashed & checked via `check_password_hash`.
# Stress that the demo must only be run in an isolated/local environment and never exposed to public networks.
# For hands-on offensive practice, recommend sandboxed, intentionally-vulnerable projects (OWASP Juice Shop, DVWA, WebGoat) that are designed for safe training.

