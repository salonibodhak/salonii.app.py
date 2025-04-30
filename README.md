import streamlit as st
import sqlite3
import hashlib
import time
import os
from cryptography.fernet import Fernet

# --- Security Setup ---
KEY_FILE = "fernet.key"

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

KEY = get_or_create_key()
cipher = Fernet(KEY)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect("performance_ledger.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            hash TEXT NOT NULL,
            prev_hash TEXT
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON ledger (timestamp)')
    conn.commit()
    conn.close()

def compute_hash(data, prev_hash):
    record = data + (prev_hash or '')
    return hashlib.sha256(record.encode()).hexdigest()

def add_entry(data):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    encrypted_data = cipher.encrypt(data.encode()).decode()
    
    conn = sqlite3.connect("performance_ledger.db")
    c = conn.cursor()
    c.execute("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else None
    curr_hash = compute_hash(encrypted_data, prev_hash)
    
    c.execute("INSERT INTO ledger (timestamp, encrypted_data, hash, prev_hash) VALUES (?, ?, ?, ?)",
              (timestamp, encrypted_data, curr_hash, prev_hash))
    conn.commit()
    conn.close()

def get_latest_entries(limit=10):
    conn = sqlite3.connect("performance_ledger.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, encrypted_data FROM ledger ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    decrypted_entries = []
    for ts, ed in rows:
        try:
            decrypted = cipher.decrypt(ed.encode()).decode()
            decrypted_entries.append((ts, decrypted))
        except Exception as e:
            decrypted_entries.append((ts, f"Decryption error: {e}"))
    return decrypted_entries

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Performance Ledger", layout="centered")
st.title("🔐 Secure Performance Ledger")

init_db()

with st.form("entry_form"):
    new_data = st.text_area("Enter performance data", height=100, placeholder="e.g., CPU: 34%, Memory: 76%")
    submitted = st.form_submit_button("Add Entry")
