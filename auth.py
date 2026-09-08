"""
TelegramCloud User Management & Auth Module
Handles multi-user authentication, roles, password hashing, admin verification codes, and live session tracking.
"""

import os
import json
import uuid
import random
import logging
import threading
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

logger = logging.getLogger(__name__)

class User(UserMixin):
    def __init__(self, user_id: str, username: str, role: str = "user", status: str = "active"):
        self.id = user_id
        self.username = username
        self.role = role
        self.status = status

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

class SessionManager:
    def __init__(self, filepath: str = "./schema/sessions.json"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self.sessions: dict = {}  # {session_id: {...}}
        self._load_sessions()

    def _load_sessions(self):
        with self._lock:
            dir_name = os.path.dirname(self.filepath) or "."
            os.makedirs(dir_name, exist_ok=True)
            if os.path.exists(self.filepath):
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        self.sessions = json.load(f)
                except Exception as e:
                    logger.error(f"Error loading sessions: {e}")
                    self.sessions = {}
            else:
                self.sessions = {}

    def _save_sessions_unlocked(self):
        try:
            dir_name = os.path.dirname(self.filepath) or "."
            os.makedirs(dir_name, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, indent=4)
        except Exception as e:
            logger.error(f"Failed saving sessions: {e}")

    def create_session(self, user_id: str, username: str, role: str, ip_address: str, user_agent: str) -> str:
        session_id = str(uuid.uuid4())
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        ua_summary = user_agent[:120] if user_agent else "Unknown Browser/Device"
        with self._lock:
            self.sessions[session_id] = {
                "session_id": session_id,
                "user_id": user_id,
                "username": username,
                "role": role,
                "ip_address": ip_address or "127.0.0.1",
                "user_agent": ua_summary,
                "login_time": now_str,
                "last_activity": now_str,
                "status": "active"
            }
            self._save_sessions_unlocked()
        return session_id

    def touch_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._lock:
            sess = self.sessions.get(session_id)
            if not sess or sess.get("status") != "active":
                return False
            sess["last_activity"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            return True

    def revoke_session(self, session_id: str) -> tuple[bool, str]:
        with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                self._save_sessions_unlocked()
                return True, f"Session '{session_id[:8]}...' revoked successfully."
            return False, "Session not found."

    def invalidate_all_sessions(self, target_username: str = None) -> int:
        count = 0
        with self._lock:
            if target_username:
                to_delete = [s_id for s_id, s_data in self.sessions.items() if s_data.get("username") == target_username]
            else:
                to_delete = list(self.sessions.keys())
            
            for s_id in to_delete:
                del self.sessions[s_id]
                count += 1
            self._save_sessions_unlocked()
        return count

    def get_sessions(self, target_username: str = None, is_admin: bool = False) -> list[dict]:
        with self._lock:
            res = []
            for s_id, s_data in self.sessions.items():
                if is_admin or not target_username or s_data.get("username") == target_username:
                    res.append(dict(s_data))
            res.sort(key=lambda x: x.get("last_activity", ""), reverse=True)
            return res

class UserManager:
    def __init__(self, filepath: str = "./schema/users.json"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self.users: dict = {}
        self.pending_codes: dict = {}  # {username: {"code": "123456", "expires_at": datetime}}
        self._load_users()

    def _load_users(self):
        with self._lock:
            dir_name = os.path.dirname(self.filepath) or "."
            os.makedirs(dir_name, exist_ok=True)
            if os.path.exists(self.filepath):
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        self.users = json.load(f)
                except Exception as e:
                    logger.error(f"Error reading users file: {e}")
                    self.users = {}
            else:
                self.users = {}

            # Ensure default admin account exists
            admin_user = os.getenv("APP_USER_NAME", "admin").strip().lower()
            admin_pass = os.getenv("APP_PASSWORD", "admin123")

            if admin_user not in self.users:
                self.users[admin_user] = {
                    "user_id": "1",
                    "username": admin_user,
                    "password_hash": generate_password_hash(admin_pass),
                    "role": "admin",
                    "status": "active",
                    "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                }
                self._save_users_unlocked()

    def _save_users_unlocked(self):
        try:
            dir_name = os.path.dirname(self.filepath) or "."
            os.makedirs(dir_name, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            logger.error(f"Failed saving users: {e}")

    def save_users(self):
        with self._lock:
            self._save_users_unlocked()

    def authenticate(self, username: str, password: str) -> User | None:
        username = username.strip().lower()
        with self._lock:
            u_data = self.users.get(username)
            if not u_data:
                return None
            if u_data.get("status") != "active":
                return None
            if check_password_hash(u_data.get("password_hash", ""), password):
                return User(
                    user_id=u_data.get("user_id", username),
                    username=u_data.get("username", username),
                    role=u_data.get("role", "user"),
                    status=u_data.get("status", "active")
                )
            return None

    def get_user_by_id(self, user_id: str) -> User | None:
        with self._lock:
            for uname, udata in self.users.items():
                if str(udata.get("user_id")) == str(user_id) or uname == str(user_id):
                    return User(
                        user_id=udata.get("user_id", uname),
                        username=udata.get("username", uname),
                        role=udata.get("role", "user"),
                        status=udata.get("status", "active")
                    )
            return None

    def request_verification_code(self, username: str) -> tuple[bool, str, str]:
        username = username.strip().lower()
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters long.", ""
        
        with self._lock:
            if username in self.users:
                return False, "Username already exists. Please choose another username or login.", ""

            # Generate 6-digit code
            code = f"{random.randint(100000, 999999)}"
            expires_at = datetime.utcnow() + timedelta(minutes=30)
            self.pending_codes[username] = {
                "code": code,
                "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            logger.info(f"Generated verification code {code} for requested user '{username}'")
            return True, f"Verification code generated for user '{username}'. Ask Admin for code to complete registration.", code

    def create_user_with_code(self, username: str, code: str, password: str) -> tuple[bool, str]:
        username = username.strip().lower()
        code = code.strip()

        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters long."
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters long."

        with self._lock:
            if username in self.users:
                return False, "Username is already registered."

            pending = self.pending_codes.get(username)
            if not pending:
                return False, "No verification code requested for this username. Please click 'Send Code' first."

            if pending["code"] != code:
                return False, "Invalid verification code! Please check with Admin."

            exp_dt = datetime.strptime(pending["expires_at"], "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() > exp_dt:
                del self.pending_codes[username]
                return False, "Verification code has expired. Please request a new code."

            # Code valid -> create user
            new_id = str(len(self.users) + 1)
            self.users[username] = {
                "user_id": new_id,
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": "user",
                "status": "active",
                "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
            del self.pending_codes[username]
            self._save_users_unlocked()
            logger.info(f"New user '{username}' registered successfully!")
            return True, f"Account '{username}' created successfully! You can now log in."

    def change_password(self, username: str, old_pass: str, new_pass: str) -> tuple[bool, str]:
        username = username.strip().lower()
        if not new_pass or len(new_pass) < 6:
            return False, "New password must be at least 6 characters long."

        with self._lock:
            udata = self.users.get(username)
            if not udata:
                return False, "User not found."
            if not check_password_hash(udata.get("password_hash", ""), old_pass):
                return False, "Incorrect current password."

            udata["password_hash"] = generate_password_hash(new_pass)
            self._save_users_unlocked()
            return True, "Password updated successfully!"

    def get_all_users(self) -> list[dict]:
        with self._lock:
            res = []
            for uname, udata in self.users.items():
                if udata.get("role") == "admin":
                    continue  # Keep admin hidden from public lists
                res.append({
                    "user_id": udata.get("user_id"),
                    "username": udata.get("username"),
                    "role": udata.get("role"),
                    "status": udata.get("status"),
                    "created_at": udata.get("created_at")
                })
            return res

    def get_pending_codes(self) -> list[dict]:
        with self._lock:
            res = []
            for uname, pdata in self.pending_codes.items():
                res.append({
                    "username": uname,
                    "code": pdata.get("code"),
                    "expires_at": pdata.get("expires_at")
                })
            return res

    def toggle_user_status(self, username: str) -> tuple[bool, str]:
        username = username.strip().lower()
        with self._lock:
            udata = self.users.get(username)
            if not udata:
                return False, "User not found."
            if udata.get("role") == "admin":
                return False, "Cannot deactivate admin account."
            
            new_status = "inactive" if udata.get("status") == "active" else "active"
            udata["status"] = new_status
            self._save_users_unlocked()
            return True, f"User '{username}' status updated to {new_status}."

    def admin_reset_password(self, username: str, new_pass: str) -> tuple[bool, str]:
        username = username.strip().lower()
        with self._lock:
            udata = self.users.get(username)
            if not udata:
                return False, "User not found."
            udata["password_hash"] = generate_password_hash(new_pass)
            self._save_users_unlocked()
            return True, f"Password for '{username}' reset successfully."

session_manager = SessionManager(filepath="./schema/sessions.json")
