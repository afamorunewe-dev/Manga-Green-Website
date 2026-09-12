from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'

# File paths for persistence
USERS_FILE = 'users.json'
SESSIONS_FILE = 'sessions.json'

# In-memory cache for performance
registered_users = {}
active_sessions = {}
attempts_tracking = {}

def load_users():
    """Load users from JSON file"""
    global registered_users
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                registered_users = json.load(f)
        except:
            registered_users = {"admin": generate_password_hash("MrBeastBeast")}
            save_users()
    else:
        registered_users = {"admin": generate_password_hash("MrBeastBeast")}
        save_users()

def save_users():
    """Save users to JSON file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(registered_users, f, indent=2)

def load_sessions():
    """Load sessions from JSON file"""
    global active_sessions
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, 'r') as f:
                active_sessions = json.load(f)
                # Clean up expired sessions
                clean_expired_sessions()
        except:
            active_sessions = {}
    else:
        active_sessions = {}

def save_sessions():
    """Save sessions to JSON file"""
    with open(SESSIONS_FILE, 'w') as f:
        json.dump(active_sessions, f, indent=2)

def clean_expired_sessions():
    """Remove expired sessions"""
    expired = [token for token, data in active_sessions.items() 
               if datetime.fromisoformat(data.get('expires', datetime.now().isoformat())) < datetime.now()]
    for token in expired:
        del active_sessions[token]
    if expired:
        save_sessions()

def create_session(username):
    """Create a new session token"""
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(days=7)
    active_sessions[token] = {
        'username': username,
        'created': datetime.now().isoformat(),
        'expires': expires.isoformat()
    }
    save_sessions()
    return token

def verify_session(token):
    """Verify if session token is valid"""
    clean_expired_sessions()
    if token in active_sessions:
        session_data = active_sessions[token]
        expires = datetime.fromisoformat(session_data['expires'])
        if expires > datetime.now():
            return session_data['username']
    return None

def get_user_attempts(username):
    """Get failed attempts for a user"""
    return attempts_tracking.get(username, 0)

def increment_attempts(username):
    """Increment failed attempts"""
    attempts_tracking[username] = get_user_attempts(username) + 1

def reset_attempts(username):
    """Reset failed attempts"""
    if username in attempts_tracking:
        del attempts_tracking[username]

# Load data on startup
load_users()
load_sessions()

# ========================================================
# API ROUTES (JSON RESPONSES)
# ========================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    """API endpoint for login"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    # Check attempts
    attempts = get_user_attempts(username)
    if attempts >= 5:
        return jsonify({
            'success': False,
            'message': 'Account locked. Too many failed attempts.',
            'locked': True
        }), 403

    # Verify credentials
    if username in registered_users and check_password_hash(registered_users[username], password):
        reset_attempts(username)
        token = create_session(username)
        return jsonify({
            'success': True,
            'message': f'Welcome back, {username}!',
            'token': token,
            'username': username
        }), 200
    else:
        increment_attempts(username)
        attempts_left = 5 - get_user_attempts(username)
        return jsonify({
            'success': False,
            'message': 'Invalid username or password',
            'attempts_left': attempts_left
        }), 401

@app.route("/api/register", methods=["POST"])
def api_register():
    """API endpoint for registration"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    if username in registered_users:
        return jsonify({'success': False, 'message': 'Username already taken'}), 409

    # Hash password and save
    registered_users[username] = generate_password_hash(password)
    save_users()
    reset_attempts(username)

    return jsonify({
        'success': True,
        'message': f'Account created successfully! You can now login.'
    }), 201

@app.route("/api/verify-session", methods=["POST"])
def api_verify_session():
    """Verify if a session token is valid"""
    data = request.get_json()
    token = data.get('token', '')

    username = verify_session(token)
    if username:
        return jsonify({
            'success': True,
            'username': username
        }), 200
    else:
        return jsonify({
            'success': False,
            'message': 'Session expired or invalid'
        }), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logout and invalidate session"""
    data = request.get_json()
    token = data.get('token', '')

    if token in active_sessions:
        del active_sessions[token]
        save_sessions()

    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ========================================================
# WEB ROUTES (FOR TESTING IN BROWSER)
# ========================================================

@app.route("/", methods=["GET"])
def home():
    """Simple page to test the API"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Skibiyastrish Auth Server</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f0f0f0; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            h1 { color: #333; }
            .info { background: #e3f2fd; padding: 10px; border-radius: 4px; margin: 10px 0; }
            code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Skibiyastrish Auth Server Running</h1>
            <p>The Flask authentication backend is active and ready for connections.</p>
            
            <div class="info">
                <strong>API Endpoints:</strong><br>
                <code>POST /api/login</code> - Login with username/password<br>
                <code>POST /api/register</code> - Register new account<br>
                <code>POST /api/verify-session</code> - Check if session is valid<br>
                <code>POST /api/logout</code> - Logout and invalidate session
            </div>
            
            <div class="info">
                <strong>Data Persistence:</strong><br>
                ✓ Users stored in <code>users.json</code><br>
                ✓ Sessions stored in <code>sessions.json</code><br>
                ✓ Data survives server restarts
            </div>
            
            <div class="info">
                <strong>Security:</strong><br>
                ✓ Passwords hashed with Werkzeug<br>
                ✓ Session tokens valid for 7 days<br>
                ✓ Account lockout after 5 failed attempts
            </div>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    print("🔐 Starting Skibiyastrish Auth Server...")
    print("📁 Data saved to: users.json, sessions.json")
    print("🌐 Server running at http://localhost:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
