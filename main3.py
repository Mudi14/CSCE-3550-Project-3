from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time
import os
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from argon2 import PasswordHasher

# Database file name
db_file = "totally_not_my_privateKeys.db"

# Fetch the encryption key from the environment variable
encryption_key = os.environ.get("NOT_MY_KEY").encode('utf-8')

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

def encrypt_private_key(key):
    return encrypt_data(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
def decrypt_private_key(key):
    return decrypt_data(key)

iv = modes.CBC(os.urandom(16))

# Function to encrypt data using AES
def encrypt_data(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(encryption_key), iv)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

# Function to decrypt data using AES
def decrypt_data(ciphertext):
    cipher = Cipher(algorithms.AES(encryption_key), iv)
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    return plaintext

# Function to create the keys table if it doesn't exist
def create_keys_table():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to insert a key into the database
def insert_key(key, exp):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    conn.commit()
    conn.close()

# Function to retrieve an unexpired or expired key
def get_key(expired=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT * FROM keys WHERE exp <= ?", (int(time.time()),))
    else:
        cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    row = cursor.fetchone()
    conn.close()
    return row

def get_keys():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    rows = cursor.fetchall()
    conn.close()
    return rows

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


# Function to create the users table
def create_users_table():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

ph = PasswordHasher()

# Function to register a new user
def register_user(username, email):
    # Generate a secure password using UUIDv4
    generated_password = str(uuid.uuid4())
    
    # Hash the password using Argon2
    hashed_password = ph.hash(generated_password)
    print("1hashed"+ hashed_password)

    # Insert user details into the database
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
    conn.commit()
    conn.close()

    return generated_password

def update_user_last_login(username):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (datetime.datetime.utcnow(),username))
    conn.commit()
    conn.close()

def fetch_user(username, password):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None
    try:
        if ph.verify(row[2], password):
            return row
    except:
        return None

    return None

# Function to create the auth_logs table
def create_auth_logs_table():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    
# Function to log authentication requests
def log_authentication_request(request_ip, user_id):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    conn.commit()
    conn.close()

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Modified the do_POST method
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            body_length = int(self.headers["Content-Length"])
            data = json.loads(self.rfile.read(body_length).decode('utf-8'))
            user = fetch_user(data["username"], data["password"])
            if user is None:
                self.send_response(401)
                self.end_headers
                return
            userID = user[0]
            username = user[1]

            update_user_last_login(username)            
            log_authentication_request(self.client_address[0], userID)
            # Retrieve the private key from the database
            key = get_key('expired' in params)
            if key is not None:
                headers = {
                    "kid": str(key[0])
                }
                token_payload = {
                    "subj": user[1],
                    "exp": key[2]
                }
                private_key = serialization.load_pem_private_key(decrypt_private_key(key[1]), None)
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Private key not found.")
            return
        elif parsed_path.path == "/register":
           body_length = int(self.headers["Content-Length"])
           data = json.loads(self.rfile.read(body_length).decode('utf-8'))
           password = register_user(data["username"], data["email"])
           self.send_response(200)
           self.end_headers()
           self.wfile.write(json.dumps({"password": password}).encode('utf-8'))

    # Modified the do_GET method
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys = get_keys()
            jwks = []
            print(keys)
            for key in keys:
                numbers = serialization.load_pem_private_key(key[1], None).private_numbers()
                jwks.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key[0]),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            resp = {
                "keys": jwks
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(resp), "utf-8"))
            return

if __name__ == "__main__":
    create_keys_table()
    insert_key(encrypt_private_key(private_key), int(time.time() + 1000))
    insert_key(encrypt_private_key(expired_key), int(time.time() - 1000))
    
    create_users_table()
    create_auth_logs_table()
    
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
