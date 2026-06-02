import hashlib
import hmac
import base64
import json
import time
from database import get_db

SECRET = "fsr_safescan_secret_2025_key"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def create_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": int(time.time()) + 86400 * 7  # 7 kun
    }
    data = base64.b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"

def verify_token(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        data, sig = parts
        expected = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.b64decode(data).decode())
        if payload["exp"] < int(time.time()):
            return None
        return payload
    except:
        return None

def register_user(username: str, email: str, password: str) -> dict:
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hash_password(password))
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return {"success": True, "user": dict(user)}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()

def login_user(username: str, password: str) -> dict:
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user or not verify_password(password, user["password_hash"]):
        return {"success": False, "error": "Foydalanuvchi nomi yoki parol noto'g'ri"}
    token = create_token(user["id"], user["username"], user["role"])
    return {"success": True, "token": token, "username": user["username"], "role": user["role"]}
