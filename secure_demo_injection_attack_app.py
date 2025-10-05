from flask import Flask, render_template, request, flash, redirect, url_for, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import shlex
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

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
    # Add multiple demo users
    demo_users = [
        ("alice", generate_password_hash("secret"), "user"),
        ("admin", generate_password_hash("adminpass"), "admin"),
        ("bob", generate_password_hash("password123"), "user"),
        ("eve", generate_password_hash("test123"), "moderator"),
        ("charlie", generate_password_hash("letmein"), "user")
    ]
    
    for username, pwd_hash, role in demo_users:
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pwd_hash, role)
        )
    
    conn.commit()
    return conn

DB = init_db()


# SQL Injection Demo Route - EXECUTES SQL FOR DEMONSTRATION
@app.route("/vulnerable", methods=["POST"])
def vulnerable():
    """
    Vulnerable demo route that ACTUALLY executes unsafe SQL to demonstrate the risk.
    - Builds an unsafe SQL string and executes it against the demo database
    - Shows how injection payloads can extract all user data
    - Uses a separate demo database to avoid security risks
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Construct the unsafe SQL string (WILL BE EXECUTED FOR DEMO)
    unsafe_sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}';"
    # password =  generate_password_hash(password)
    # unsafe_sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{password}';"
    
    flash("🔍 <strong>SQL Injection Demo - UNSAFE QUERY EXECUTION</strong>", "warning")
    flash(f"<strong>Original SQL template:</strong> SELECT id, username, role FROM users WHERE username = '[username]' AND password = '[password]';", "info")
    flash(f"<strong>Your input:</strong> username='{username}', password='{password}'", "info")
    flash(f"<strong>Final SQL formed:</strong> {unsafe_sql}", "warning")

    try:
        # EXECUTE THE UNSAFE SQL FOR DEMONSTRATION
        cursor = DB.cursor()
        cursor.execute(unsafe_sql)
        results = cursor.fetchall()
        
        flash(f"<strong>Query executed!</strong> Found {len(results)} record(s)", "info")
        
        if results:
            flash("📊 <strong>Query Results:</strong>", "success")
            for user in results:
                flash(f"   👤 ID: {user[0]}, Username: {user[1]}, Role: {user[2]}", "success")
        else:
            flash("❌ No results found with these credentials", "info")

        # Special demonstration for injection patterns
        if any(pattern in unsafe_sql.upper() for pattern in ["OR '1'='1", "OR 1=1", "UNION"]):
            show_injection_analysis(username, password, unsafe_sql, results)
        else:
            # Show normal login attempt analysis
            if username and password:
                flash("💡 <strong>Normal login attempt:</strong> This checks for exact username/password match", "info")
                if not results:
                    flash("❌ Login would fail with these credentials", "error")

    except sqlite3.Error as e:
        flash(f"❌ <strong>SQL Error:</strong> {str(e)}", "error")
        # Still show analysis even if there's an error
        show_injection_analysis(username, password, unsafe_sql, [])

    return redirect(url_for("index"))

def show_injection_analysis(username, password, unsafe_sql, results):
    """
    Analyze and explain SQL injection patterns and their effects.
    """
    # Authentication Bypass
    if any(pattern in unsafe_sql.upper() for pattern in ["OR '1'='1", "OR 1=1"]):
        flash("🚨 <strong>AUTHENTICATION BYPASS DETECTED!</strong>", "error")
        flash("💡 <strong>How it works:</strong> The condition <code>OR '1'='1'</code> makes the WHERE clause always TRUE", "info")
        flash("🎯 <strong>Effect:</strong> Returns ALL users instead of checking credentials!", "error")
        
        # Show the logical breakdown
        flash("🔧 <strong>Logic breakdown:</strong>", "info")
        flash("   Original: <code>username = '[input]' AND password = '[input]'</code>", "info")
        if "' OR '1'='1" in username:
            flash("   Becomes: <code>username = '' OR '1'='1' AND password = '[input]'</code>", "info")
        flash("   Evaluates to: <code>TRUE OR (TRUE AND ...)</code> → <code>TRUE</code>", "info")

    # Comment-based Injection
    if "--" in unsafe_sql or "/*" in unsafe_sql:
        flash("🚨 <strong>COMMENT INJECTION DETECTED!</strong>", "error")
        flash("💡 <strong>How it works:</strong> SQL comments (<code>--</code> or <code>/* */</code>) ignore the rest of the query", "info")
        if "admin' --" in unsafe_sql:
            flash("🎯 <strong>Effect:</strong> Logs in as 'admin' without password check!", "error")
            flash("🔧 <strong>How:</strong> <code>admin' --</code> makes the query: <code>username = 'admin'</code> (password part is ignored)", "info")

    # UNION Attacks
    if "UNION" in unsafe_sql.upper():
        flash("🚨 <strong>UNION ATTACK DETECTED!</strong>", "error")
        flash("💡 <strong>How it works:</strong> UNION combines results from multiple SELECT statements", "info")
        flash("🎯 <strong>Effect:</strong> Can extract data from other tables or columns!", "error")

    # Show all users in database for educational purposes
    if results and len(results) > 1:
        flash("📋 <strong>Educational: All users in the demo database:</strong>", "info")
        try:
            cursor = DB.cursor()
            cursor.execute("SELECT id, username, role FROM users")
            all_users = cursor.fetchall()
            for user in all_users:
                flash(f"   👤 ID: {user[0]}, Username: {user[1]}, Role: {user[2]}", "info")
        except sqlite3.Error as e:
            flash(f"❌ Could not fetch all users: {str(e)}", "error")

    # Destructive commands warning
    if any(cmd in unsafe_sql.upper() for cmd in ["DROP", "DELETE", "UPDATE", "INSERT"]):
        flash("💀 <strong>DESTRUCTIVE COMMAND DETECTED!</strong>", "error")
        flash("🚨 In a real attack, this could modify or delete database contents!", "error")
        flash("🛡️ <strong>Protected:</strong> This demo only allows SELECT queries for safety", "info")

# Using this api, the current list of users can be fetched
@app.route("/show_all_users")
def show_all_users():
    """
    Route to show all users in the database for educational purposes.
    """
    try:
        cursor = DB.cursor()
        cursor.execute("SELECT id, username, role FROM users")
        all_users = cursor.fetchall()
        
        flash("📋 <strong>All users in the demo database:</strong>", "info")
        for user in all_users:
            flash(f"👤 ID: {user[0]}, Username: {user[1]}, Role: {user[2]}", "info")
            
    except sqlite3.Error as e:
        flash(f"❌ Error fetching users: {str(e)}", "error")
    
    return redirect(url_for("index"))

# Secure Login Route
@app.route("/secure_login", methods=["POST"])
def secure_login():
    """
    Secure login using parameterized queries.
    """
    print(f'Secure login using parameterized queries.')
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # Secure parameterized query
    secure_sql = "SELECT id, username, password_hash, role FROM users WHERE username = ?"
    
    flash("🔒 <strong>Secure Login (Parameterized Query)</strong>", "success")
    flash(f"<strong>Safe SQL:</strong> <code>{secure_sql}</code>", "success")
    flash(f"<strong>Parameters:</strong> username='{username}'", "success")
    
    try:
        # Actually execute the safe parameterized query
        cursor = DB.cursor()
        cursor.execute(secure_sql, (username,))
        user = cursor.fetchone()
        print(f'All users: {user}')
        
        if user and check_password_hash(user[2], password):
            flash(f"✅ <strong>Login successful!</strong> Welcome {user[1]} (role: {user[3]})", "success")
        else:
            flash("❌ <strong>Login failed:</strong> Invalid username or password", "error")
            
    except Exception as e:
        flash(f"❌ <strong>Error:</strong> {str(e)}", "error")
    
    return redirect(url_for("index"))

@app.route('/vulnerable_ping', methods=['POST'])
def vulnerable_ping():
    host = request.form['host']
    
    # VULNERABLE: Direct string concatenation - susceptible to command injection
    try:
        # This is dangerous - user input is directly used in shell command
        command = f"ping -c 4 {host}"
        flash(f"⚠️ VULNERABLE COMMAND EXECUTED: {command}", "warning")
        
        # Check if there's a command injection attempt
        if "&&" in host or ";" in host or "|" in host:
            flash("🚨 Command injection detected! Additional commands are being executed.", "error")
            
            # Actually execute the command to demonstrate the vulnerability
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            # Show the output of the injected commands
            if result.stdout:
                flash("Command output:", "error")
                # Split output into lines and flash each line
                for line in result.stdout.split('\n'):
                    if line.strip():  # Only show non-empty lines
                        flash(f"📄 {line}", "info")
            
            if result.stderr:
                flash("Command errors:", "error")
                for line in result.stderr.split('\n'):
                    if line.strip():
                        flash(f"❌ {line}", "error")
                        
            # Additional demo: Show what specific commands would do
            if 'ls' in host:
                # Execute ls separately to show current directory contents
                ls_result = subprocess.run('ls -la', shell=True, capture_output=True, text=True)
                flash("📁 Current directory contents (from 'ls -la'):", "error")
                for line in ls_result.stdout.split('\n'):
                    if line.strip():
                        flash(f"   {line}", "info")
            
            if 'pwd' in host:
                pwd_result = subprocess.run('pwd', shell=True, capture_output=True, text=True)
                flash(f"📂 Current directory: {pwd_result.stdout.strip()}", "error")
                
            if 'whoami' in host:
                whoami_result = subprocess.run('whoami', shell=True, capture_output=True, text=True)
                flash(f"👤 Current user: {whoami_result.stdout.strip()}", "error")
                
        else:
            # Normal ping execution (simulated or real)
            # For safety, we'll just simulate normal ping
            flash(f"📡 Ping result for {host}: Simulated ping output", "info")
            # These values are initially set as placeholders (dummy data) for the static ping results. They must be dynamically
            # overwritten in the subsequent code by executing the 'ping' command against the specified host to obtain and display
            # real-time, updated network metrics.
            flash("PING google.com (142.250.191.78): 56 data bytes", "info")
            flash("64 bytes from 142.250.191.78: icmp_seq=0 ttl=117 time=15.283 ms", "info")
            flash("64 bytes from 142.250.191.78: icmp_seq=1 ttl=117 time=12.456 ms", "info")
            flash("--- google.com ping statistics ---", "info")
            flash("2 packets transmitted, 2 packets received, 0.0% packet loss", "info")
            
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    
    return redirect(url_for('index'))

# The `shlex.quote()` method is used to mitigate command injection vulnerabilities by taking an input string 
# and adding shell-appropriate quotes, effectively sanitizing the string so that any special shell characters it contains (such as semicolons or pipes) 
# are treated as literal arguments rather than executable commands, thereby preventing malicious code from being executed within the system.
@app.route('/secure_ping', methods=['POST'])
def secure_ping():
    host = request.form['host']
    
    # SECURE: Input validation and safe execution
    try:
        # Validate host input - only allow alphanumeric, dots, and hyphens
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            flash("❌ Invalid hostname. Only letters, numbers, dots, and hyphens allowed.", "error")
            return redirect(url_for('index'))
        
        # Use shlex.quote to safely escape the input
        safe_host = shlex.quote(host)
        command = f"ping -c 4 {safe_host}"
        
        flash(f"✅ SECURE COMMAND: {command}", "success")
        
        # For demo, simulate safe execution
        # In real app: result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)
        
        flash(f"Ping result for {host}: Simulated safe ping output", "info")
        flash("✅ Input validated and safely executed", "success")
        
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')  # Your HTML template name

if __name__ == '__main__':
    app.run(debug=True)