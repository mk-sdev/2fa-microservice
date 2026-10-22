import base64
import io
import logging

import psycopg2
import redis
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, jsonify, request

from ..audit import audit_log
from ..config import DATABASE_URL
from ..security import (
    clear_failed_attempts,
    generate_backup_codes,
    is_rate_limited,
    make_auth_response,
    ph,
    record_failed_attempt,
    require_auth,
)

bp = Blueprint('backup_codes', __name__)

@bp.route("/verify-backup-code", methods=["DELETE"])
@require_auth
def verify_backup_code(user_id):
    """Verifies backup code using Argon2 hashes"""
    action = "verify-backup-code"

    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "BACKUP_CODE_VERIFY_RATE_LIMITED")
            return jsonify({"error": "Too many attempts. Try again later."}), 429
    except redis.RedisError:
        current_app.logger.exception("Redis error during backup code verification")
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
        current_app.logger.exception("Redis error during backup code verification")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception:
        current_app.logger.exception("Failed to verify backup code")
        return jsonify({"error": "Unable to verify backup code"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()



@bp.route("/regenerate-backup-codes", methods=["POST"])
@require_auth
def regenerate_backup_codes(user_id):
    action = "regenerate-backup-codes"
    try:
        if is_rate_limited(user_id, action):
            audit_log(logging.WARNING, user_id, "BACKUP_CODES_REGENERATE_RATE_LIMITED")
            return jsonify({"error": "Too many attempts. Try again later."}), 429
    except redis.RedisError:
        current_app.logger.exception("Redis error during backup code regeneration")
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
        current_app.logger.exception("Redis error during backup code regeneration")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500




