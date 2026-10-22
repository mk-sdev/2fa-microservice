from flask import Flask, request, jsonify
import pyotp
import jwt
import datetime
import qrcode
import io
import base64
import json
import psycopg2
from flask_cors import CORS
from dotenv import load_dotenv
import os
import redis
from cryptography.fernet import Fernet
import string
import random
import secrets
import logging
from logging.handlers import RotatingFileHandler
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

os.makedirs("logs", exist_ok=True)
audit_handler = RotatingFileHandler(
    "logs/flask-2fa-audit.log", maxBytes=10 * 1024 * 1024, backupCount=5
)
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)
audit_logger.propagate = False

r = redis.Redis(host="redis", port=6379, db=0, decode_responses=True)

CORS(
    app,
    supports_credentials=True,  # allows sending cookies
    origins=[
        "http://localhost:4200",  
        "http://localhost:4201",  
    ]
)


load_dotenv()

JWT_ACCESS_SECRET = os.getenv("JWT_ACCESS_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")
JWT_2FA_SECRET = os.getenv("JWT_2FA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")
ISSUER = "IAM System"
FERNET_KEY = os.getenv("TOTP_ENCRYPTION_KEY")

fernet = Fernet(FERNET_KEY)


def audit_log(level, user_id, action, details=None):
    """Write Auth-Service-compatible JSON audit records without credentials."""
    record = {
        "level": logging.getLevelName(level).lower(),
        "userId": str(user_id) if user_id is not None else "anonymous",
        "action": action,
        "details": {
            "ip": request.headers.get(
                "X-Forwarded-For", request.remote_addr or "unknown"
            ).split(",")[0].strip(),
            "path": request.path,
            "method": request.method,
            **(details or {}),
        },
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    audit_logger.log(level, json.dumps(record, separators=(",", ":")))

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

ph = PasswordHasher()

def store_backup_codes(user_id, codes):
    """Stores backup codes hashed with Argon2"""
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    for code in codes:
        hashed = ph.hash(code)
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

from functools import wraps

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401
        return f(user_id, *args, **kwargs)
    return wrapper


@app.route("/enable-2fa", methods=["PATCH"])
@require_auth
def enable_2fa(user_id):
    '''
    Generates a secret for 2FA setup, creates a provisioning URI, and returns a QR code for the user to scan.
    The secret is stored in otp_secret until the user confirms 2FA setup.
    '''

    conn = None

    try:
        conn = psycopg2.connect(DATABASE_URL)

        with conn.cursor() as cur:
            cur.execute("""
                SELECT is_2fa_enabled
                FROM users
                WHERE _id = %s
            """, (user_id,))

            row = cur.fetchone()

            if not row:
                return jsonify({"error": "User not found"}), 404

            if row[0]:
                return jsonify({"error": "2FA is already enabled"}), 409

            secret = pyotp.random_base32()
            encrypted_secret = encrypt_secret(secret)

            cur.execute("""
                UPDATE users
                SET otp_secret = %s
                WHERE _id = %s
            """, (encrypted_secret, user_id))

        conn.commit()

        totp = pyotp.TOTP(secret)

        uri = totp.provisioning_uri(
            name=str(user_id),
            issuer_name=ISSUER
        )

        # QR
        qr = qrcode.make(uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")

        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return jsonify({
            "qr_base64": qr_base64
        })

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Failed to initialize 2FA")
        return jsonify({"error": "Unable to initialize 2FA"}), 500

    finally:
        if conn:
            conn.close()


@app.route("/confirm-2fa", methods=["POST"])
@require_auth
def confirm_2fa(user_id):
    '''
    Verifies the 2FA code entered by the user against the secret stored in the database.
    If the code is valid, 2FA is enabled for the user.
    '''

    action = "confirm-2fa"
    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "2FA_CONFIRM_RATE_LIMITED")
            return jsonify({"error": "Too many attempts. Try again later."}), 429
    except redis.RedisError:
        app.logger.exception("Redis error during 2FA confirmation")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        audit_log(logging.WARNING, user_id, "2FA_CONFIRM_INVALID_REQUEST")
        return jsonify({"error": "Invalid request"}), 400

    conn = None

    try:
        conn = psycopg2.connect(DATABASE_URL)

        with conn.cursor() as cur:
            cur.execute("""
                SELECT otp_secret, is_2fa_enabled
                FROM users
                WHERE _id = %s
                FOR UPDATE
            """, (user_id,))

            row = cur.fetchone()

            if not row:
                return jsonify({"error": "User not found"}), 404

            encrypted_secret, is_enabled = row

            if is_enabled:
                return jsonify({"error": "2FA is already enabled"}), 409

            if not encrypted_secret:
                return jsonify({"error": "2FA not initialized"}), 400

            secret = decrypt_secret(encrypted_secret)
            totp = pyotp.TOTP(secret)

            if not totp.verify(code, valid_window=1):
                record_failed_attempt(user_id, action)
                audit_log(logging.WARNING, user_id, "2FA_CONFIRM_INVALID_CODE")
                return jsonify({"error": "Invalid code"}), 401

            cur.execute("""
                UPDATE users
                SET is_2fa_enabled = TRUE
                WHERE _id = %s
            """, (user_id,))

            # Generate backup codes after successful 2FA confirmation
            backup_codes = generate_backup_codes()

            for backup_code in backup_codes:
                cur.execute("""
                    INSERT INTO backup_codes (user_id, code)
                    VALUES (%s, %s)
                """, (user_id, ph.hash(backup_code)))

        conn.commit()
        clear_failed_attempts(user_id, action)
        audit_log(logging.INFO, user_id, "2FA_ENABLED")

        return jsonify({
            "message": "2FA enabled",
            "backup_codes": backup_codes  # shown only once to the user
        })

    except redis.RedisError:
        if conn:
            conn.rollback()
        app.logger.exception("Redis error during 2FA confirmation")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Failed to confirm 2FA")
        return jsonify({"error": "Unable to confirm 2FA"}), 500

    finally:
        if conn:
            conn.close()


@app.route("/disable-2fa", methods=["PATCH"])
@require_auth
def disable_2fa(user_id):
    '''
    Disables 2FA for the user by clearing otp_secret, otp_temp_secret,
    is_2fa_enabled, and deleting all backup codes for the user
    '''

    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # remove backup codes
        cur.execute("""
            DELETE FROM backup_codes
            WHERE user_id = %s
        """, (user_id,))

        # turn off 2FA and clear secrets
        cur.execute("""
            UPDATE users
            SET otp_secret = NULL,
                otp_temp_secret = NULL,
                is_2fa_enabled = FALSE
            WHERE _id = %s
        """, (user_id,))

        conn.commit()
        cur.close()
        conn.close()

        audit_log(logging.INFO, user_id, "2FA_DISABLED")
        return jsonify({"message": "2FA disabled and backup codes removed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/2fa-info", methods=["GET"])
@require_auth
def twofa_info(user_id):
    '''
    Checks if 2FA is enabled for the user and if so, counts how many backup codes are left
    '''
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # 1. 2FA status
    cur.execute("""
        SELECT is_2fa_enabled
        FROM users
        WHERE _id = %s
    """, (user_id,))
    user_row = cur.fetchone()

    if not user_row:
        cur.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    is_2fa_enabled = user_row[0]

    # 2. backup codes count
    cur.execute("""
        SELECT COUNT(*)
        FROM backup_codes
        WHERE user_id = %s
    """, (user_id,))
    backup_count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return jsonify({
        "isTwoFactorEnabled": is_2fa_enabled,
        "backupCodesLeft": backup_count
    })


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


@app.route("/verify-2fa", methods=["PATCH"])
@require_auth
def verify_2fa(user_id):
    '''
    Verifies the 2FA code entered by the user against the otp_secret stored in the database.
    If the code is valid, generates access and refresh tokens.
    '''

    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return jsonify({"error": "Missing or invalid 2FA code"}), 400

    action = "verify-2fa"
    conn = None

    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "2FA_VERIFY_RATE_LIMITED")
            return jsonify({
                "error": "Too many attempts. Try again later."
            }), 429

        conn = psycopg2.connect(DATABASE_URL)

        with conn.cursor() as cur:
            cur.execute("""
                SELECT otp_secret, is_2fa_enabled
                FROM users
                WHERE _id = %s
            """, (user_id,))

            row = cur.fetchone()

        if not row:
            return jsonify({"error": "User not found"}), 404

        encrypted_secret, is_enabled = row

        if not is_enabled or not encrypted_secret:
            return jsonify({"error": "2FA not enabled"}), 400

        secret = decrypt_secret(encrypted_secret)
        totp = pyotp.TOTP(secret)

        if not totp.verify(code, valid_window=1):
            record_failed_attempt(user_id, action)
            audit_log(logging.WARNING, user_id, "2FA_VERIFY_INVALID_CODE")

            return jsonify({"error": "Invalid code"}), 401

        clear_failed_attempts(user_id, action)
        audit_log(logging.INFO, user_id, "2FA_VERIFIED")

        return make_auth_response(
            {"message": "2FA verified"},
            user_id
        )

    except redis.RedisError:
        app.logger.exception("Redis error during 2FA verification")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    except Exception:
        app.logger.exception("Failed to verify 2FA")
        return jsonify({"error": "Unable to verify 2FA"}), 500

    finally:
        if conn:
            conn.close()


@app.route("/verify-backup-code", methods=["DELETE"])
@require_auth
def verify_backup_code(user_id):
    """Verifies backup code using Argon2 hashes"""
    action = "verify-backup-code"

    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "BACKUP_CODE_VERIFY_RATE_LIMITED")
            return jsonify({"error": "Too many attempts. Try again later."}), 429
    except redis.RedisError:
        app.logger.exception("Redis error during backup code verification")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not isinstance(code, str) or not code:
        audit_log(logging.WARNING, user_id, "BACKUP_CODE_VERIFY_INVALID_REQUEST")
        return jsonify({"error": "Invalid request"}), 400

    conn = None
    cur = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        cur.execute(
            "SELECT id, code FROM backup_codes WHERE user_id = %s",
            (user_id,)
        )
        rows = cur.fetchall()

        if not rows:
            audit_log(logging.WARNING, user_id, "BACKUP_CODE_VERIFY_NO_CODES")
            return jsonify({"error": "No backup codes available"}), 400

        matched_id = None

        for backup_id, code_hash in rows:
            try:
                if ph.verify(code_hash, code):
                    matched_id = backup_id
                    break
            except VerifyMismatchError:
                continue

        if not matched_id:
            record_failed_attempt(user_id, action)
            audit_log(logging.WARNING, user_id, "BACKUP_CODE_VERIFY_INVALID")
            return jsonify({"error": "Invalid backup code"}), 401

        # Consume the backup code once it has been verified.
        cur.execute("DELETE FROM backup_codes WHERE id = %s", (matched_id,))
        conn.commit()
        clear_failed_attempts(user_id, action)

        audit_log(logging.INFO, user_id, "BACKUP_CODE_VERIFIED")
        return make_auth_response({"message": "Backup code verified"}, user_id)
    except redis.RedisError:
        app.logger.exception("Redis error during backup code verification")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception:
        app.logger.exception("Failed to verify backup code")
        return jsonify({"error": "Unable to verify backup code"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/regenerate-backup-codes", methods=["POST"])
@require_auth
def regenerate_backup_codes(user_id):
    action = "regenerate-backup-codes"
    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "BACKUP_CODES_REGENERATE_RATE_LIMITED")
            return jsonify({"error": "Too many attempts. Try again later."}), 429
    except redis.RedisError:
        app.logger.exception("Redis error during backup code regeneration")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    data = request.get_json(silent=True) or {}
    password = data.get("password")

    if not isinstance(password, str) or not password:
        audit_log(logging.WARNING, user_id, "BACKUP_CODES_REGENERATE_INVALID_REQUEST")
        return jsonify({"error": "Password is required"}), 400

    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # get user's password hash
        cur.execute("""
            SELECT password
            FROM users
            WHERE _id = %s
        """, (user_id,))

        row = cur.fetchone()

        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        password_hash = row[0]

        # verify password using Argon2
        try:
            ph.verify(password_hash, password)
        except VerifyMismatchError:
            record_failed_attempt(user_id, action)
            audit_log(logging.WARNING, user_id, "BACKUP_CODES_REGENERATE_INVALID_PASSWORD")
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid password"}), 401

        # delete old backup codes
        cur.execute("""
            DELETE FROM backup_codes
            WHERE user_id = %s
        """, (user_id,))

        # generate new ones
        new_codes = generate_backup_codes()

        # save them hashed in the database
        for code in new_codes:
            hashed = ph.hash(code)
            cur.execute(
                "INSERT INTO backup_codes (user_id, code) VALUES (%s, %s)",
                (user_id, hashed)
            )

        conn.commit()
        clear_failed_attempts(user_id, action)
        audit_log(
            logging.INFO,
            user_id,
            "BACKUP_CODES_REGENERATED",
            {"count": len(new_codes)},
        )
        cur.close()
        conn.close()

        # return plain codes to the user
        return jsonify({
            "message": "Backup codes regenerated",
            "backup_codes": new_codes
        })

    except redis.RedisError:
        app.logger.exception("Redis error during backup code regeneration")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
