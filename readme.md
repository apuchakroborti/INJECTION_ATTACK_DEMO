# SQL & Command Injection Demo

A Flask-based educational web application that demonstrates SQL Injection and Command Injection vulnerabilities in a safe, controlled environment. This project helps developers understand how these attacks work and how to prevent them.

## 🚀 Features

### SQL Injection Demo
- **Vulnerable Login**: Shows how SQL injection bypasses authentication
- **Secure Login**: Demonstrates parameterized queries protection
- **Live Query Analysis**: Displays how SQL queries are formed and executed
- **Multiple Attack Vectors**: 
  - Authentication bypass (`' OR '1'='1`)
  - Comment-based injection (`admin' --`)
  - UNION attacks
  - Data extraction techniques

### Command Injection Demo
- **Vulnerable Ping**: Demonstrates command injection in system commands
- **Secure Ping**: Shows input validation and safe execution
- **Real Command Execution**: Safely demonstrates attack consequences
  - Directory listing (`ls`)
  - Current user detection (`whoami`)
  - System information disclosure

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Step-by-Step Setup

1. **Clone or download the project files**
   ```bash
   # If using git
   git clone <repository-url>
   cd security-demo
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install required dependencies**
   ```bash
   pip install flask werkzeug
   ```

4. **Project Structure**
   ```
   security-demo/
   ├── secure_demo_injection_attack_app.py              # Main Flask application
   ├── templates/
   │   └── index.html      # Web interface
   └── README.md
   ```

5. **Run the application**
   ```bash
   python3 secure_demo_injection_attack_app.py
   ```

6. **Access the demo**
   - Open your web browser
   - Navigate to: `http://localhost:5000`
   - The demo interface will load

## 🎯 How to Use

### SQL Injection Testing

1. **Try Normal Login**
   - Username: `alice`
   - Password: `secret`

2. **Test SQL Injection Attacks**
   - Username: `' OR '1'='1` (shows all users)
   - Username: `admin' --` (bypass password)
   - Username: `' UNION SELECT 1,2,3 --` (data extraction)

3. **Compare with Secure Login**
   - Same inputs but using parameterized queries
   - See how injection attempts fail

### Command Injection Testing

1. **Normal Ping**
   - Host: `google.com`

2. **Test Command Injection**
   - Host: `google.com && ls` (lists directory)
   - Host: `google.com ; whoami` (shows current user)
   - Host: `google.com | pwd` (shows current directory)

3. **Compare with Secure Ping**
   - Input validation prevents command injection
   - Only allows valid hostnames

## 🔒 Security Features

- **In-Memory Database**: Uses SQLite in-memory database for safety
- **No Real Damage**: All destructive commands are simulated
- **Educational Focus**: Clear explanations of vulnerabilities and fixes
- **Controlled Environment**: Safe demonstration without real-world risks

## 📚 Learning Objectives

After using this demo, you'll understand:

### SQL Injection
- How string concatenation in SQL creates vulnerabilities
- Why parameterized queries prevent injection
- Common SQL injection patterns and their effects
- How to properly sanitize user input

### Command Injection
- Dangers of unsanitized user input in system commands
- Importance of input validation and allow-listing
- Safe command execution practices
- Using `subprocess` safely in Python

## 🛡️ Prevention Techniques Demonstrated

### SQL Injection Prevention
- Parameterized queries with `?` placeholders
- Proper use of database cursors
- Separation of code and data

### Command Injection Prevention
- Input validation with regular expressions
- Using `shlex.quote()` for safe string handling
- Executing commands without `shell=True`
- Using command arrays instead of string concatenation

## 🎮 Demo Users

The application includes these test users:
- **alice** / **secret** (regular user)
- **admin** / **adminpass** (admin user)
- **bob** / **password123** (regular user)
- **eve** / **test123** (moderator)
- **charlie** / **letmein** (regular user)

## ⚠️ Important Notes

- This is for **EDUCATIONAL PURPOSES ONLY**
- Never use vulnerable code in production
- Always validate and sanitize user input
- Use parameterized queries for all database operations
- The demo uses an in-memory database that resets on restart

## 🔧 Troubleshooting

### Common Issues

1. **"Template not found" error**
   - Ensure `templates` folder exists with `index.html`

2. **Import errors**
   - Run `pip install flask werkzeug` to install dependencies

3. **Port already in use**
   - Change port: `app.run(debug=True, port=5001)`

4. **Command execution errors**
   - Some commands might not work on Windows
   - Demo uses safe simulation for destructive commands

## 📖 Further Learning

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Flask Security Guidelines](https://flask.palletsprojects.com/en/stable/security/)
- [Python Security Best Practices](https://docs.python.org/3/library/security.html)

## 📄 License

This project is intended for educational purposes. Use responsibly and only in controlled environments.

---

**Remember**: Security is a continuous process. Always stay updated with the latest security practices and regularly audit your code for vulnerabilities!