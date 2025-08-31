import os
import psycopg2
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# خواندن آدرس دیتابیس از متغیرهای محیطی که در Render تنظیم می‌کنیم
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """یک اتصال جدید به دیتابیس برقرار می‌کند."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """جداول مورد نیاز را در دیتابیس می‌سازد."""
    conn = get_db_connection()
    cur = conn.cursor()
    # ساخت جدول کاربران
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )''')
    # ساخت جدول رمزها
    cur.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    owner TEXT NOT NULL REFERENCES users(username),
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )''')
    conn.commit()
    cur.close()
    conn.close()
    print("Tables initialized successfully.")

# این تابع را یک بار در ابتدای برنامه اجرا می‌کنیم
init_db()

@app.route('/')
def home():
    return "PassGuard Server is live and connected to the permanent database!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    password_hash = generate_password_hash(password)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 21
    except psycopg2.IntegrityError:
        conn.rollback() # برگرداندن تغییرات در صورت خطا
        return jsonify({"error": "Username already exists"}), 400
    finally:
        cur.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
    user_data = cur.fetchone()
    cur.close()
    conn.close()
    
    if user_data and check_password_hash(user_data[0], password):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/add_password', methods=['POST'])
def add_password():
    data = request.get_json()
    owner = data.get('owner') 
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')
    if not all([owner, website, username, password]):
        return jsonify({"error": "Missing data"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO passwords (owner, website, username, password) VALUES (%s, %s, %s, %s)",
                (owner, website, username, password))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password added successfully"}), 201

@app.route('/get_passwords', methods=['GET'])
def get_passwords():
    owner = request.args.get('owner')
    if not owner:
        return jsonify({"error": "Owner username is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, website, username, password FROM passwords WHERE owner = %s", (owner,))
    passwords = cur.fetchall()
    cur.close()
    conn.close()
    
    pass_list = [{"id": row[0], "website": row[1], "username": row[2], "password": row[3]} for row in passwords]
    return jsonify(pass_list)

# (دیگر به if __name__ == '__main__': نیازی نیست چون Gunicorn برنامه را اجرا می‌کند)
