from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    print("Database opened successfully")
    # ساخت جدول کاربران
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)')
    # --- ساخت جدول جدید برای رمزها ---
    conn.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner TEXT NOT NULL,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    FOREIGN KEY (owner) REFERENCES users (username)
                )''')
    print("Tables created successfully")
    conn.close()

init_db()

@app.route('/')
def home():
    return "PassGuard Server is active."

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user_data = cur.fetchone()
    conn.close()

    if user_data and check_password_hash(user_data[0], password):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid username or password"}), 401

# --- مسیر جدید برای اضافه کردن رمز ---
@app.route('/add_password', methods=['POST'])
def add_password():
    data = request.get_json()
    # در آینده اینجا باید از توکن امنیتی استفاده کنیم
    owner = data.get('owner') 
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not all([owner, website, username, password]):
        return jsonify({"error": "Missing data"}), 400
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO passwords (owner, website, username, password) VALUES (?, ?, ?, ?)",
                (owner, website, username, password))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password added successfully"}), 201

# --- مسیر جدید برای گرفتن لیست رمزها ---
@app.route('/get_passwords', methods=['GET'])
def get_passwords():
    owner = request.args.get('owner') # گرفتن نام کاربری از URL
    if not owner:
        return jsonify({"error": "Owner username is required"}), 400

    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT id, website, username, password FROM passwords WHERE owner = ?", (owner,))
    passwords = cur.fetchall()
    conn.close()
    
    # تبدیل نتیجه به لیست دیکشنری
    pass_list = []
    for row in passwords:
        pass_list.append({
            "id": row[0],
            "website": row[1],
            "username": row[2],
            "password": row[3]
        })
    return jsonify(pass_list)


if __name__ == '__main__':
    app.run(debug=True)
