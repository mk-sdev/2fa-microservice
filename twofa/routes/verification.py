import base64
import io
import logging

import psycopg2
import pyotp
import qrcode
import redis
from flask import Blueprint, current_app, jsonify, request

from ..audit import audit_log
from ..config import DATABASE_URL
from ..security import (
    clear_failed_attempts,
    decrypt_secret,
    is_rate_limited,
    make_auth_response,
    normalize_totp_code,
    record_failed_attempt,
    require_auth,
)

bp = Blueprint('verification', __name__)

@bp.route("/verify-2fa", methods=["PATCH"])
@require_auth
def verify_2fa(user_id):
    '''
    Verifies the 2FA code entered by the user against the otp_secret stored in the database.
    If the code is valid, generates access and refresh tokens.
    '''

    data = request.get_json(silent=True) or {}
    code = normalize_totp_code(data.get("code"))

    if code is None:
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
        current_app.logger.exception("Redis error during 2FA verification")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    except Exception:
        current_app.logger.exception("Failed to verify 2FA")
        return jsonify({"error": "Unable to verify 2FA"}), 500

    finally:
        if conn:
            conn.close()




