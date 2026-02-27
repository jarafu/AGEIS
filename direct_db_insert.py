import sqlite3
from werkzeug.security import generate_password_hash

db_path = 'instance/threat_reports.db'

# --- User Data ---
username = "socmanager"
email = "socmanager@example.com"
password = "Manager123!"
role = "manager"
approved = True

# --- Hash Password ---
password_hash = generate_password_hash(password)

# --- Connect to Database ---
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# --- Check if user exists ---
cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
user = cursor.fetchone()

if user:
    # --- Update existing user ---
    cursor.execute("""
        UPDATE user
        SET password_hash = ?, email = ?, role = ?, approved = ?
        WHERE username = ?
    """, (password_hash, email, role, approved, username))
    print(f"User '{username}' has been updated.")
else:
    # --- Insert new user ---
    cursor.execute("""
        INSERT INTO user (username, email, password_hash, role, approved)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, role, approved))
    print(f"User '{username}' has been created.")

# --- Commit and Close ---
conn.commit()
conn.close()
