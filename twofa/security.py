import datetime
import secrets
import string
from functools import wraps

import jwt
import psycopg2
import redis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import jsonify, request

from .config import (
    DATABASE_URL,
    JWT_ACCESS_SECRET,
    JWT_2FA_SECRET,
    JWT_REFRESH_SECRET,
    PEPPER,
    fernet,
)

r = redis.Redis(host="redis", port=6379, db=0, decode_responses=True)


def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(encrypted_secret: str) -> str:
    return fernet.decrypt(encrypted_secret.encode()).decode()

def generate_tokens(user_id):
    access_payload = {
        "sub": user_id,
        "2fa": True,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }

    refresh_payload = {
        "sub": user_id,
        "2fa": True,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

    return (
        jwt.encode(access_payload, JWT_ACCESS_SECRET, algorithm="HS256"),
        jwt.encode(refresh_payload, JWT_REFRESH_SECRET, algorithm="HS256")
    )

def make_auth_response(payload, user_id):
    response = jsonify(payload)

    access_token, refresh_token = generate_tokens(user_id)

    response.set_cookie("access_token", access_token, httponly=True, secure=False, samesite="lax", max_age=15*60)
    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="lax", max_age=60*60)

    return response

def generate_backup_codes(n=10, length=8):
    """Generates a list of n random backup codes, each of specified length"""
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]


def normalize_totp_code(code):
    """Return a six-digit TOTP string from a JSON string or integer."""
    if isinstance(code, bool):
        return None
    if isinstance(code, int) and 0 <= code <= 999999:
        return f"{code:06d}"
    if isinstance(code, str) and len(code) == 6 and code.isdigit():
        return code
    return None

ph = PasswordHasher()


def hash_preimage(preimage):
    """Hash a value after appending the configured pepper."""
    return ph.hash(preimage + PEPPER)


def verify_preimage(hashed_value, preimage):
    """Verify with pepper; optionally accept pre-pepper backup code hashes."""
    try:
        return ph.verify(hashed_value, preimage + PEPPER)
    except VerifyMismatchError:
        raise

def store_backup_codes(user_id, codes):
    """Stores backup codes hashed with Argon2"""
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    for code in codes:
        hashed = hash_preimage(code)
        cur.execute(
            "INSERT INTO backup_codes (user_id, code) VALUES (%s, %s)",
            (user_id, hashed)
        )

    conn.commit()
    cur.close()
    conn.close()

def get_user_id_from_token():
    '''
    Helper fucntion to extract user ID from either access token or 2fa token in cookies
    '''
    token = request.cookies.get("access_token") or request.cookies.get("2fa_token")
    if not token:
        return None

    try:
        if request.cookies.get("2fa_token") == token:
            payload = jwt.decode(token, JWT_2FA_SECRET, algorithms=["HS256"])
        else:
            payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401
        return f(user_id, *args, **kwargs)
    return wrapper



RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300


def rate_limit_key(user_id, action):
    return f"rate-limit:{action}:{user_id}"


def is_rate_limited(user_id, action, limit=RATE_LIMIT_ATTEMPTS):
    attempts = r.get(rate_limit_key(user_id, action))
    return attempts is not None and int(attempts) >= limit


def record_failed_attempt(user_id, action):
    """Atomically count a failed attempt and start its fixed window."""
    key = rate_limit_key(user_id, action)
    with r.pipeline() as pipe:
        pipe.incr(key)
        pipe.expire(key, RATE_LIMIT_WINDOW_SECONDS, nx=True)
        pipe.execute()


def clear_failed_attempts(user_id, action):
    r.delete(rate_limit_key(user_id, action))



