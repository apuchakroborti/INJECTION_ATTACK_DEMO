### What the demo does (safe)

* Serves a small Flask web page with a login form.
* The **“Vulnerable (demo)”** handler builds the unsafe SQL string and prints it to the server console (so you can see how user input is interpolated into SQL).

  * **It does not execute that unsafe SQL**, so the app cannot be used to practice bypassing credentials.
* The **“Secure”** handler uses a parameterized SQLite query to check credentials and demonstrates the correct pattern to prevent SQL injection.
* The app seeds an in-memory SQLite database with one test user (username `alice`, password `secret`) so you can try logging in properly.


1. Save the code below as `secure_demo.py`.
2. `pip install flask` (if needed).
3. Run: `python secure_demo.py`
4. Visit `http://127.0.0.1:5000/` in your browser.
5. Try the **Secure login** with `alice` / `secret`. The vulnerable route will show the constructed SQL (printed in server console) but will not execute it.


### Teaching talking points while demoing

* Show the printed query from the **Vulnerable (demo)** route in the server console and point out how user input ended up *inside quotes* in the SQL. Explain why that allows an attacker to change the meaning of the query if they can control the input.
* Emphasize: **we are not executing the constructed unsafe SQL** in this demo — that keeps the demo safe.
* Then show the **Secure login** route:

  * Explain how `?` placeholders and the parameter tuple ensure the DB driver treats input purely as data.
  * Demonstrate logging in successfully with `alice` / `secret`.
* Discuss additional mitigations:

  * Use hashed & salted passwords (bcrypt / Argon2) instead of storing plaintext.
  * Use least privilege DB accounts.
  * Use ORMs that parameterize queries automatically.
  * Input validation and allowlist where appropriate.
  * Logging / WAF / regular security testing.

---

### If you want to practice exploit demonstration safely

If your goal is *security training that includes practicing attacks*, use an intentionally vulnerable training environment (these are **designed** for safe practice and sandboxed):

* **OWASP Juice Shop** — full-featured intentionally vulnerable web app.
* **Damn Vulnerable Web Application (DVWA)** — classic training app.
* **WebGoat** — interactive lessons.

Those projects are designed exactly for hands-on learning, containment, and legal/ethical practice. I recommend using them rather than adapting a simple demo into an exploitable service.

---

If you want, I can:

* Extend the demo to show **how to store passwords safely** (bcrypt demo), or
* Provide **slides/snippets** explaining the vulnerability and fix for your workshop, or
* Show an **ORM example** (SQLAlchemy) with safe query patterns.

Which of these would help you next?
