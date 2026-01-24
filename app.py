from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import sqlite3
import traceback
import subprocess
import os
import pickle
import base64
import time
import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, make_response

import logging

# VULNERABILITY: Security Logging Failure (CWE-532) - Logging sensitive data
logging.basicConfig(filename='app.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'super_secret_key'

def init_db():
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT DEFAULT 'user', balance INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, image TEXT)''')
    
    c.execute("INSERT OR IGNORE INTO users (id, username, password, role, balance) VALUES (1, 'admin', 'admin_pass_123', 'admin', 1000)")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, role, balance) VALUES (2, 'student', '123456', 'user', 10)")
    
    # Check if products exist
    c.execute("SELECT count(*) FROM products")
    if c.fetchone()[0] == 0:
        books = [
            ("Onyx Storm (The Empyrean, #3)", 32.00), ("Sunrise on the Reaping", 29.00), ("Great Big Beautiful Life", 29.00), 
            ("Atmosphere", 28.00), ("The Crash", 18.00), ("The Tenant", 16.00), ("James", 24.00), ("On Tyranny", 14.00),
            ("Careless People", 22.00), ("Parable of the Sower", 19.00), ("Martyr!", 18.00), ("I Who Have Never Known Men", 17.00),
            ("The Widow", 25.00), ("Speak to Me of Home", 30.00), ("The Body Keeps the Score", 20.00),
            ("Atomic Habits", 23.00), ("The Women", 28.00), ("Iron Flame", 30.00), ("Fourth Wing", 25.00), ("A Court of Thorns and Roses", 18.00),
            ("The Midnight Library", 16.00), ("Yellowface", 26.00), ("Tom Lake", 27.00), ("Demon Copperhead", 24.00), ("Happy Place", 24.00),
            ("Hello Beautiful", 28.00), ("Lessons in Chemistry", 22.00), ("Tomorrow, and Tomorrow, and Tomorrow", 25.00), ("Remarkably Bright Creatures", 23.00), ("It Ends with Us", 15.00),
            ("Verity", 16.00), ("It Starts with Us", 17.00), ("The Seven Husbands of Evelyn Hugo", 16.00), ("Daisy Jones & The Six", 17.00), ("Malibu Rising", 18.00),
            ("Project Hail Mary", 20.00), ("The Silent Patient", 14.00), ("Where the Crawdads Sing", 12.00), ("Dune", 18.00), ("1984", 10.00),
            ("Brave New World", 11.00), ("Fahrenheit 451", 12.00), ("The Catcher in the Rye", 10.00), ("The Great Gatsby", 10.00), ("Pride and Prejudice", 9.00),
            ("To Kill a Mockingbird", 12.00), ("Jane Eyre", 10.00), ("Wuthering Heights", 10.00), ("Little Women", 11.00), ("Moby Dick", 13.00)
        ]
        for name, price in books:
            c.execute("INSERT INTO products (name, price) VALUES (?, ?)", (name, price))
        
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    conn.close()
    return render_template('index.html', products=products)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    # VULNERABILITY: SQL Injection (Search)
    # We will use a standard vulnerable query since the user asked for vulnerabilities in the project generally,
    # though the login is the specific one requested. Let's make this one safe(r) or vulnerable? 
    # Use vulnerable search since it's a vulnerable shop.
    sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    try:
        c.execute(sql_query)
        products = c.fetchall()
    except Exception as e:
        products = []
        logging.error(f"Search error: {e}")
    conn.close()
    return render_template('index.html', products=products, search_query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # VULNERABILITY: Mass Assignment / Insecure Default
        # The user can pick their role directly from the form!
        role = request.form.get('role', 'user')
        
        conn = sqlite3.connect('shop.db')
        c = conn.cursor()
        try:
            # We use a vulnerable insert? No, let's just make the role vulnerable.
            # Using param substitution for registration to ensure it works reliably (we have enough SQLi elsewhere)
            c.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
                      (username, password, role, 100))
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect('/')
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY: Security Logging Failure (CWE-532)
        # Logging the raw password is a critical failure.
        logging.info(f"Login attempt for user: {username} with password: {password}")

        # VULNERABILITY: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        # Also logging the raw query exposes the password again
        logging.debug(f"Executing Query: {query}")

        conn = sqlite3.connect('shop.db')
        c = conn.cursor()
        try:
            c.execute(query)
            user = c.fetchone()
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                logging.info(f"User {username} logged in successfully.")
                flash(f"Login Successful! (SQL Injection Solved)", "success")
                resp = make_response(redirect('/'))
                # VULNERABILITY: A01:2025 Broken Access Control
                # Relying on a simple cookie for role definition (Parameter Tampering)
                resp.set_cookie('role', user[3], httponly=False) 
                return resp
            else:
                logging.warning(f"Failed login for {username}")
                flash("Error: Invalid credentials", "danger")
        except Exception as e:
            logging.error(f"SQL Error during login: {e}")
            flash(f"SQL Error: {e}", "warning")
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.set_cookie('role', '', expires=0)
    return resp

# --- NEW VULNERABILITIES ---

# 1. A01:2025 Broken Access Control
# Scenario #2: Admin page accessible by anyone who manipulates the cookie or knows the URL
@app.route('/admin')
def admin_panel():
    # VULNERABILITY: Checks cookie instead of server-side session
    user_role = request.cookies.get('role')
    if user_role == 'admin':
        return render_template('admin.html', flag="ACCESS_CONTROL_BYPASSED_SUCCESS")
    else:
        return "<h1>403 Forbidden</h1><p>You must be an admin. Current role: " + str(user_role) + "</p>", 403

# 2. A10:2025 Mishandling of Exceptional Conditions
# Scenario #2: Revealing full system error to the user (Stack Trace Leak)
@app.route('/debug')
def debug_page():
    try:
        # Simulate a crash
        x = 1 / 0
    except Exception as e:
        # VULNERABILITY: Return full traceback to user
        error_msg = traceback.format_exc()
        return f"<h1>500 Internal Server Error</h1><pre>{error_msg}</pre>"

# 3. A03:2025 Software Supply Chain Failures
# Scenario #4: Component with a backdoor (Simulated)
# We simulate a 'trusted' payment component that has a hardcoded backdoor
@app.route('/payment', methods=['POST'])
def payment():
    # Helper to simulate a 3rd party lib processing
    def process_payment_lib(card_number):
        # Secure processing - Backdoor removed
        return True, "Payment Processed via Standard Gateway"

    card = request.form.get('card_number')
    success, msg = process_payment_lib(card)
    return jsonify({"status": success, "message": msg})


# 4. A06:2025 Insecure Design
# Scenario #2: Client-side pricing (Trusting client input for business logic)
@app.route('/buy', methods=['POST'])
def buy_item():
    item_id = request.form.get('item_id')
    # VULNERABILITY: The price is accepted directly from the form!
    price = request.form.get('price') 
    
    return jsonify({
        "status": "success", 
        "message": f"Bought item {item_id} for ${price}! (Insecure Design: You set the price!)"
    })

@app.route('/api_lab')
def api_lab():
    return render_template('api_docs.html')

# --- NEW OWASP API SECURITY 2023 VULNERABILITIES ---

# 1. API3:2023 Broken Object Property Level Authorization (BOPLA) / Mass Assignment
# Vulnerability: Allows updating 'balance' field which should be restricted.
@app.route('/api/v2/user/update', methods=['POST'])
def update_profile():
    if not session.get('user_id'):
        return jsonify({"error": "Unauthorized"}), 401
    
    # User sends JSON: {"username": "newname", "balance": 999999}
    data = request.json
    user_id = session['user_id']
    
    # VULNERABLE: Iterates over ALL provided keys and updates them, including 'balance'
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    try:
        for key, value in data.items():
            # Dangerous dynamic query construction
            query = f"UPDATE users SET {key} = ? WHERE id = ?"
            c.execute(query, (value, user_id))
        conn.commit()
        return jsonify({"status": "success", "message": "Profile updated", "data": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 2. API4:2023 Unrestricted Resource Consumption
# Vulnerability: Allows allocating large lists based on user input (DoS vector)
@app.route('/api/v2/logs')
def get_logs():
    # User can control 'limit'. Try ?limit=100000000
    limit = int(request.args.get('limit', 10))
    
    # VULNERABLE: No upper bound on limit. Memory exhaustion possible.
    results = ["Log Entry " + str(i) for i in range(limit)]
    return jsonify({"count": len(results), "logs": results[:10]}) # returning partial but allocating all

# 3. API7:2023 Server Side Request Forgery (SSRF)
# Vulnerability: Server fetches arbitrary URL provided by user
@app.route('/api/v2/profile/image_url', methods=['POST'])
def fetch_profile_image():
    # User sends {"url": "http://internal-service/secret"}
    target_url = request.json.get('url')
    
    try:
        # VULNERABLE: No filtering of internal IPs or schemes
        resp = requests.get(target_url, timeout=5)
        return jsonify({"status": "success", "image_size": len(resp.content), "content_preview": resp.text[:100]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 4. API9:2023 Improper Inventory Management
# Vulnerability: Zombie API (v1) still active, has no authentication
@app.route('/api/v1/users/all')
def list_users_v1():
    # VULNERABLE: This is an old endpoint that should have been deprecated. No Auth check.
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return jsonify({"version": "v1 (deprecated)", "users": users})

# 5. API2:2023 Broken Authentication
# Vulnerability: Password Reset returns the token to the user
@app.route('/api/v2/password_reset/start', methods=['POST'])
def password_reset_start():
    username = request.json.get('username')
    # Generate a "random" token
    token = f"reset_token_for_{username}_12345"
    
    # VULNERABLE: The API returns the sensitive token in the response!
    return jsonify({
        "status": "pending",
        "message": "Reset link sent to email (simulated)",
        "debug_token": token # OOPS!
    })


# ---------------------------

@app.route('/api/orders/<order_id>')
def get_order(order_id):
    # VULNERABILITY: BOLA / IDOR (No ownership check)
    orders = {
        "1": {"item": "Python Book", "price": 50, "owner_id": 1},
        "2": {"item": "Cyber Secrets (FLAG: BOLA_KING)", "price": 0, "owner_id": 2},
        "3": {"item": "Admin Master Key", "cc_number": "4580-1234-5678-9012", "owner_id": 1}
    }
    data = orders.get(order_id)
    if data:
        return jsonify(data)
    return jsonify({"error": "Order not found"}), 404

@app.route('/chat')
def chat_ui():
    return render_template('chat.html')

@app.route('/chat_api', methods=['POST'])
def chat_api():
    # VULNERABILITY: LLM Prompt Injection Simulation
    user_msg = request.json.get('message', '').lower()
    response_text = "I am a sales bot. I cannot reveal secrets."
    solved = False
    
    # Vulnerabilitiy Removed: 'Developer Mode' keywords no longer work
    if "flag" in user_msg or "secret" in user_msg:
        response_text = "I cannot reveal the secret."
        
    return jsonify({"reply": response_text, "solved": solved})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
