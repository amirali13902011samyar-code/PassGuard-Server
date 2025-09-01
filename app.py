import os
import psycopg2
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- بخش امنیتی: خواندن کلیدهای مخفی از متغیرهای محیطی ---
DATABASE_URL = os.environ.get('DATABASE_URL')
SECRET_KEY = os.environ.get('SECRET_KEY')
cipher_suite = Fernet(SECRET_KEY.encode())

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
    # ساخت جدول رمزها (با نوع ستون صحیح)
    cur.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    owner TEXT NOT NULL REFERENCES users(username),
                    website BYTEA NOT NULL,
                    username BYTEA NOT NULL,
                    password BYTEA NOT NULL
                )''')
    conn.commit()
    cur.close()
    conn.close()
    print("Tables initialized successfully.")

init_db()

@app.route('/')
def home():
    return "PassGuard Server is live and secure!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing data"}), 400
    
    password_hash = generate_password_hash(password)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
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
        return jsonify({"error": "Missing data"}), 400

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
    
    encrypted_website = cipher_suite.encrypt(website.encode())
    encrypted_username = cipher_suite.encrypt(username.encode())
    encrypted_password = cipher_suite.encrypt(password.encode())
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO passwords (owner, website, username, password) VALUES (%s, %s, %s, %s)",
                (owner, encrypted_website, encrypted_username, encrypted_password))
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
    
    pass_list = []
    for row in passwords:
        pass_list.append({
            "id": row[0],
            "website": cipher_suite.decrypt(row[1]).decode(),
            "username": cipher_suite.decrypt(row[2]).decode(),
            "password": cipher_suite.decrypt(row[3]).decode()
        })
    return jsonify(pass_list)

@app.route('/edit_password', methods=['POST'])
def edit_password():
    data = request.get_json()
    p_id = data.get('id')
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    encrypted_website = cipher_suite.encrypt(website.encode())
    encrypted_username = cipher_suite.encrypt(username.encode())
    encrypted_password = cipher_suite.encrypt(password.encode())

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE passwords SET website = %s, username = %s, password = %s WHERE id = %s",
                (encrypted_website, encrypted_username, encrypted_password, p_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password updated successfully"})

@app.route('/delete_password', methods=['POST'])
def delete_password():
    data = request.get_json()
    p_id = data.get('id')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id = %s", (p_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password deleted successfully"})
