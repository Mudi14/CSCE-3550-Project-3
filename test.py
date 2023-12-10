import unittest
import sqlite3
import time
import json
import requests
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from http.server import HTTPServer, BaseHTTPRequestHandler
from main3 import create_keys_table, insert_key, get_key, get_keys, int_to_base64, MyServer

# Define a test database file
test_db_file = "test_privateKeys.db"

class TestMyServer(unittest.TestCase):
    def setUp(self):
        # Set up a clean test database and create the keys table
        self.conn = sqlite3.connect(test_db_file)
        self.create_keys_table()
        self.private_key, self.pem = self.generate_test_key()

    def tearDown(self):
        # Clean up and close the database connection
        self.conn.close()

    def create_keys_table(self):
        # Create the keys table for testing
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        self.conn.commit()

    def generate_test_key(self):
        # Generate a test key and return it along with its PEM representation
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key, pem

    def test_create_keys_table(self):
        # Test the create_keys_table function
        create_keys_table()
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
        result = cursor.fetchone()
        self.assertIsNotNone(result)

    def test_insert_key_and_get_key(self):
        # Test the insert_key and get_key functions
        exp_time = int(time.time()) + 1000
        insert_key(self.pem, exp_time)
        key = get_key()
        self.assertIsNotNone(key)
        self.assertEqual(key[2], exp_time)

    def test_get_keys(self):
        # Test the get_keys function
        insert_key(self.pem, int(time.time()) + 1000)
        keys = get_keys()
        self.assertIsNotNone(keys)
        self.assertEqual(len(keys), 1)

    def test_int_to_base64(self):
        # Test the int_to_base64 function
        value = 123456789
        encoded = int_to_base64(value)
        self.assertEqual(encoded, "AQIDBAU=")

    def test_do_GET_jwks_endpoint(self):
        # Test the do_GET method for the JWKS endpoint using real HTTP requests
        server = HTTPServer(("localhost", 0), MyServer)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
        try:
            # Make a real HTTP GET request to the server
            response = requests.get(f"http://localhost:{server.server_address[1]}/.well-known/jwks.json")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["Content-type"], "application/json")
            jwks = response.json()
            self.assertEqual(len(jwks["keys"]), 1)  # Assuming one key was inserted
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join()

    def test_do_POST_auth_endpoint(self):
        # Test the do_POST method for the auth endpoint using real HTTP requests
        server = HTTPServer(("localhost", 0), MyServer)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
        try:
            # Make a real HTTP POST request to the server
            response = requests.post(f"http://localhost:{server.server_address[1]}/auth", data={"expired": "false"})

            self.assertEqual(response.status_code, 500)  # Private key not found in this case
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join()

if __name__ == '__main__':
    unittest.main()
