import json
import logging
import uuid

import psycopg2
import redis
from flask import Blueprint, current_app, jsonify, request
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..audit import audit_log
from ..config import (
    WEBAUTHN_CHALLENGE_TTL,
    WEBAUTHN_ORIGIN,
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
)
from ..security import (
    clear_failed_attempts,
    consume_2fa_token,
    generate_backup_codes,
    hash_preimage,
    is_rate_limited,
    make_auth_response,
    r,
    record_failed_attempt,
    require_2fa,
    require_auth,
)
from ..config import DATABASE_URL

bp = Blueprint('webauthn', __name__)


def _json_options(options):
    return json.loads(options_to_json(options))


def _challenge_key(user_id, ceremony):
    return f"webauthn:{ceremony}:{user_id}"


def _load_active_credentials(cur, user_id):
    cur.execute(
        "SELECT credential_id, public_key, sign_count, name FROM webauthn_credentials WHERE user_id = %s",
        (user_id,),
    )
    return cur.fetchall()


@bp.route('/webauthn/register/options', methods=['POST'])
@require_auth
def registration_options(user_id):
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return jsonify({"error": "Key name must contain 1 to 80 characters"}), 400

    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT email, twofa_method FROM users WHERE _id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            email, method = user
            credentials = _load_active_credentials(cur, user_id)
            options = generate_registration_options(
                rp_id=WEBAUTHN_RP_ID,
                rp_name=WEBAUTHN_RP_NAME,
                user_id=uuid.UUID(str(user_id)).bytes,
                user_name=email,
                user_display_name=email,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                    resident_key=ResidentKeyRequirement.DISCOURAGED,
                    user_verification=UserVerificationRequirement.DISCOURAGED,
                ),
                exclude_credentials=[
                    PublicKeyCredentialDescriptor(id=base64url_to_bytes(row[0]))
                    for row in credentials
                ],
            )
            r.set(
                _challenge_key(user_id, 'register'),
                json.dumps({"challenge": bytes_to_base64url(options.challenge), "name": name.strip(), "method": method}),
                ex=WEBAUTHN_CHALLENGE_TTL,
            )
        return jsonify(_json_options(options))
    except redis.RedisError:
        current_app.logger.exception("Redis error creating WebAuthn registration challenge")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception:
        current_app.logger.exception("Failed to create WebAuthn registration options")
        return jsonify({"error": "Unable to start security key registration"}), 500
    finally:
        if conn:
            conn.close()


@bp.route('/webauthn/register/verify', methods=['POST'])
@require_auth
def verify_registration(user_id):
    response_data = request.get_json(silent=True) or {}
    try:
        saved = r.getdel(_challenge_key(user_id, 'register'))
    except redis.RedisError:
        current_app.logger.exception("Redis error retrieving WebAuthn registration challenge")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    if not saved:
        return jsonify({"error": "Registration challenge expired or already used"}), 400

    saved = json.loads(saved)
    conn = None
    try:
        verification = verify_registration_response(
            credential=response_data,
            expected_challenge=base64url_to_bytes(saved['challenge']),
            expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            require_user_verification=False,
        )
        credential_id = bytes_to_base64url(verification.credential_id)
        public_key = bytes_to_base64url(verification.credential_public_key)

        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT twofa_method FROM users WHERE _id = %s FOR UPDATE", (user_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "User not found"}), 404
            current_method = row[0]
            cur.execute(
                "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, sign_count, name) VALUES (%s, %s, %s, %s, %s)",
                (credential_id, user_id, public_key, verification.sign_count, saved['name']),
            )

            switched = current_method != 'WEBAUTHN'
            cur.execute("UPDATE users SET otp_secret = NULL, twofa_method = 'WEBAUTHN' WHERE _id = %s", (user_id,))
            backup_codes = []
            if switched:
                cur.execute("DELETE FROM backup_codes WHERE user_id = %s", (user_id,))
                backup_codes = generate_backup_codes()
                for code in backup_codes:
                    cur.execute("INSERT INTO backup_codes (user_id, code) VALUES (%s, %s)", (user_id, hash_preimage(code)))
        conn.commit()
        audit_log(logging.INFO, user_id, 'WEBAUTHN_CREDENTIAL_REGISTERED')
        return jsonify({
            "message": "Security key registered",
            "credential": {"credential_id": credential_id, "name": saved['name']},
            "twoFactorMethod": "WEBAUTHN",
            "backup_codes": backup_codes,
        })
    except psycopg2.errors.UniqueViolation:
        if conn:
            conn.rollback()
        return jsonify({"error": "This security key is already registered"}), 409
    except Exception:
        if conn:
            conn.rollback()
        current_app.logger.exception("Failed to verify WebAuthn registration")
        return jsonify({"error": "Unable to verify security key registration"}), 400
    finally:
        if conn:
            conn.close()


@bp.route('/webauthn/credentials', methods=['GET'])
@require_auth
def list_credentials(user_id):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            credentials = _load_active_credentials(cur, user_id)
        return jsonify({"credentials": [{"credential_id": row[0], "name": row[3]} for row in credentials]})
    finally:
        conn.close()


@bp.route('/webauthn/credentials/<credential_id>', methods=['PATCH'])
@require_auth
def rename_credential(user_id, credential_id):
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return jsonify({"error": "Key name must contain 1 to 80 characters"}), 400
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE webauthn_credentials SET name = %s WHERE credential_id = %s AND user_id = %s",
                (name.strip(), credential_id, user_id),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Security key not found"}), 404
        conn.commit()
        return jsonify({"message": "Security key renamed"})
    except Exception:
        conn.rollback()
        current_app.logger.exception("Failed to rename WebAuthn credential")
        return jsonify({"error": "Unable to rename security key"}), 500
    finally:
        conn.close()


@bp.route('/webauthn/credentials/<credential_id>', methods=['DELETE'])
@require_auth
def delete_credential(user_id, credential_id):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT twofa_method FROM users WHERE _id = %s FOR UPDATE", (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            cur.execute("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = %s", (user_id,))
            count = cur.fetchone()[0]
            cur.execute(
                "DELETE FROM webauthn_credentials WHERE credential_id = %s AND user_id = %s",
                (credential_id, user_id),
            )
            if cur.rowcount == 0:
                return jsonify({"error": "Security key not found"}), 404
            if user[0] == 'WEBAUTHN' and count <= 1:
                conn.rollback()
                return jsonify({"error": "Add another security key or disable 2FA before removing the last key"}), 409
        conn.commit()
        audit_log(logging.INFO, user_id, 'WEBAUTHN_CREDENTIAL_REMOVED', {"credential_id": credential_id})
        return jsonify({"message": "Security key removed"})
    except Exception:
        conn.rollback()
        current_app.logger.exception("Failed to delete WebAuthn credential")
        return jsonify({"error": "Unable to remove security key"}), 500
    finally:
        conn.close()


@bp.route('/webauthn/authenticate/options', methods=['POST'])
@require_2fa
def authentication_options(user_id):
    action = 'webauthn-authenticate'
    if is_rate_limited(user_id, action):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT twofa_method FROM users WHERE _id = %s", (user_id,))
            method = cur.fetchone()
            credentials = _load_active_credentials(cur, user_id)
        if not method or method[0] != 'WEBAUTHN' or not credentials:
            return jsonify({"error": "WebAuthn is not the active 2FA method"}), 400
        options = generate_authentication_options(
            rp_id=WEBAUTHN_RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(row[0])) for row in credentials
            ],
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )
        r.set(
            _challenge_key(user_id, 'authenticate'),
            bytes_to_base64url(options.challenge),
            ex=WEBAUTHN_CHALLENGE_TTL,
        )
        return jsonify(_json_options(options))
    except redis.RedisError:
        current_app.logger.exception("Redis error creating WebAuthn authentication challenge")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    except Exception:
        current_app.logger.exception("Failed to create WebAuthn authentication options")
        return jsonify({"error": "Unable to start security key verification"}), 500
    finally:
        conn.close()


@bp.route('/webauthn/authenticate/verify', methods=['POST'])
@require_2fa
def verify_authentication(user_id):
    action = 'webauthn-authenticate'
    if is_rate_limited(user_id, action):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    try:
        challenge = r.getdel(_challenge_key(user_id, 'authenticate'))
    except redis.RedisError:
        current_app.logger.exception("Redis error retrieving WebAuthn authentication challenge")
        return jsonify({"error": "Authentication temporarily unavailable"}), 503
    if not challenge:
        return jsonify({"error": "Authentication challenge expired or already used"}), 400

    data = request.get_json(silent=True) or {}
    credential_id = data.get('id')
    if not isinstance(credential_id, str):
        return jsonify({"error": "Invalid credential response"}), 400

    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT twofa_method FROM users WHERE _id = %s", (user_id,))
            method = cur.fetchone()
            cur.execute(
                "SELECT public_key, sign_count FROM webauthn_credentials WHERE credential_id = %s AND user_id = %s FOR UPDATE",
                (credential_id, user_id),
            )
            stored = cur.fetchone()
            if not method or method[0] != 'WEBAUTHN' or not stored:
                record_failed_attempt(user_id, action)
                return jsonify({"error": "Invalid security key"}), 401

            verification = verify_authentication_response(
                credential=data,
                expected_challenge=base64url_to_bytes(challenge),
                expected_origin=WEBAUTHN_ORIGIN,
                expected_rp_id=WEBAUTHN_RP_ID,
                credential_public_key=base64url_to_bytes(stored[0]),
                credential_current_sign_count=int(stored[1]),
                require_user_verification=False,
            )
            if not consume_2fa_token():
                conn.rollback()
                return jsonify({"error": "This login challenge was already used"}), 401
            cur.execute(
                "UPDATE webauthn_credentials SET sign_count = %s WHERE credential_id = %s AND user_id = %s",
                (verification.new_sign_count, credential_id, user_id),
            )
        conn.commit()
        clear_failed_attempts(user_id, action)
        audit_log(logging.INFO, user_id, 'WEBAUTHN_VERIFIED')
        return make_auth_response({"message": "Security key verified"}, user_id)
    except Exception:
        if conn:
            conn.rollback()
        record_failed_attempt(user_id, action)
        audit_log(logging.WARNING, user_id, 'WEBAUTHN_VERIFY_FAILED')
        current_app.logger.exception("Failed to verify WebAuthn authentication")
        return jsonify({"error": "Invalid security key response"}), 401
    finally:
        if conn:
            conn.close()

