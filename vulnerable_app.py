"""
vulnerable_app.py — Intentionally insecure Python app for demo purposes
DO NOT USE IN PRODUCTION
"""

import hashlib
import pickle
import os
import subprocess
import random
import telnetlib
import yaml
import tempfile
import sqlite3
import requests
import xml.etree.ElementTree as ET


# ── S011: Hardcoded credentials ───────────────────────────────────────────────
password    = "admin123"
api_key     = "sk-live-abc987xyz"
secret_key  = "supersecretkey!"
auth_token  = "Bearer eyJhbGciOiJIUzI1NiJ9.payload"


# ── S001: SQL Injection ───────────────────────────────────────────────────────
def get_user(conn, username):
    cursor = conn.cursor()
    # string formatting in SQL → injectable
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchone()

def get_product(conn, product_id):
    cursor = conn.cursor()
    # f-string in SQL → also injectable
    cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")
    return cursor.fetchone()


# ── S002: Code Injection ──────────────────────────────────────────────────────
def calculate(expression):
    # eval on user input → arbitrary code execution
    return eval(expression)

def run_script(code):
    exec(code)


# ── S003: Weak Hashing ────────────────────────────────────────────────────────
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()    # MD5 is broken

def checksum(data):
    return hashlib.sha1(data).hexdigest()          # SHA-1 is broken


# ── S004: Insecure Deserialization ────────────────────────────────────────────
def load_session(raw_bytes):
    return pickle.loads(raw_bytes)                 # arbitrary code if tampered


# ── S005: Command Injection ───────────────────────────────────────────────────
def ping_host(host):
    os.system(f"ping -c 1 {host}")                # injectable via host value

def convert_file(filename):
    subprocess.run(f"convert {filename} out.pdf", shell=True)  # shell=True danger


# ── S006: SSL Verification Disabled ──────────────────────────────────────────
def fetch_data(url):
    return requests.get(url, verify=False)         # MITM possible

def post_data(url, payload):
    return requests.post(url, json=payload, verify=False)


# ── S007: XXE via XML parser ──────────────────────────────────────────────────
def parse_config(xml_string):
    return ET.fromstring(xml_string)               # vulnerable to XXE


# ── S008: Insecure Random ─────────────────────────────────────────────────────
def generate_token():
    return random.randint(100000, 999999)          # predictable

def pick_winner(users):
    return random.choice(users)


# ── S009: Unsafe YAML ─────────────────────────────────────────────────────────
def load_config(path):
    with open(path) as f:
        return yaml.load(f)                        # no Loader= → RCE possible


# ── S010: Insecure Temp File ──────────────────────────────────────────────────
def write_temp(data):
    tmp = tempfile.mktemp()                        # TOCTOU race condition
    with open(tmp, "w") as f:
        f.write(data)
    return tmp
