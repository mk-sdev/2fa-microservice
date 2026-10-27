import base64
import io
import logging

import psycopg2
import pyotp
import qrcode
import redis
from flask import Blueprint, current_app, jsonify, request

from ..audit import audit_log
from ..config import DATABASE_URL, ISSUER
from ..security import (
    clear_failed_attempts,
    decrypt_secret,
    encrypt_secret,
    generate_backup_codes,
    is_rate_limited,
    normalize_totp_code,
    ph,
    record_failed_attempt,
    require_auth,
)

bp = Blueprint('settings', __name__)

@bp.route("/enable-2fa", methods=["PATCH"])
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

        current_app.logger.exception("Failed to initialize 2FA")
        return jsonify({"error": "Unable to initialize 2FA"}), 500

    finally:
        if conn:
            conn.close()



@bp.route("/confirm-2fa", methods=["POST"])
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
        current_app.logger.exception("Redis error during 2FA confirmation")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    data = request.get_json(silent=True) or {}
    code = normalize_totp_code(data.get("code"))

    if code is None:
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
        current_app.logger.exception("Redis error during 2FA confirmation")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503

    except Exception:
        if conn:
            conn.rollback()

        current_app.logger.exception("Failed to confirm 2FA")
        return jsonify({"error": "Unable to confirm 2FA"}), 500

    finally:
        if conn:
            conn.close()



@bp.route("/disable-2fa", methods=["PATCH"])
@require_auth
def disable_2fa(user_id):
    '''
    Disables 2FA for the user by clearing otp_secret and deleting backup codes.
    '''

    print(f"Disabling 2FA for user_id: {user_id}", flush=True)
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM backup_codes
                WHERE user_id = %s
            """, (user_id,))

            cur.execute("""
                UPDATE users
                SET otp_secret = NULL,
                    is_2fa_enabled = FALSE
                WHERE _id = %s
            """, (user_id,))

        conn.commit()
        audit_log(logging.INFO, user_id, "2FA_DISABLED")
        return jsonify({"message": "2FA disabled and backup codes removed successfully"})
    except Exception:
        if conn:
            conn.rollback()
        current_app.logger.exception("Failed to disable 2FA")
        return jsonify({"error": "Unable to disable 2FA"}), 500
    finally:
        if conn:
            conn.close()



@bp.route("/2fa-info", methods=["GET"])
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
