import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

os.environ["JWT_ACCESS_SECRET"] = "test-access-secret-0123456789abcdef"
os.environ["JWT_REFRESH_SECRET"] = "test-refresh-secret-0123456789abcdef"
os.environ["JWT_2FA_SECRET"] = "test-2fa-secret-0123456789abcdef"
os.environ["DATABASE_URL"] = "postgresql://test:test@localhost/test"
os.environ["TOTP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
from twofa import security


class RefreshTokenStorageTests(unittest.TestCase):
    @patch.object(security.psycopg2, "connect")
    def test_generated_refresh_token_has_jti_and_expiry(self, connect):
        connection = MagicMock()
        connect.return_value = connection
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [("USER",)]

        _, refresh_token, token_id, token_expires = security.generate_tokens(
            "user-1"
        )

        payload = jwt.decode(
            refresh_token,
            "test-refresh-secret-0123456789abcdef",
            algorithms=["HS256"],
        )
        self.assertEqual(payload["jti"], token_id)
        self.assertEqual(payload["sub"], "user-1")
        self.assertAlmostEqual(payload["exp"], token_expires.timestamp(), delta=1)

    @patch.object(security.psycopg2, "connect")
    @patch.object(security, "hash_preimage", return_value="argon-hash")
    @patch.object(
        security,
        "generate_tokens",
        return_value=(
            "access-jwt",
            "refresh-jwt",
            "refresh-id",
            datetime.now(timezone.utc) + timedelta(hours=1),
        ),
    )
    def test_auth_response_stores_hash_id_and_expiry(
        self, generate_tokens, hash_preimage, connect
    ):
        connection = MagicMock()
        connect.return_value = connection

        from flask import Flask

        with Flask(__name__).app_context():
            security.make_auth_response({"message": "2FA verified"}, "user-1")

        cursor = connection.cursor.return_value.__enter__.return_value
        sql, params = cursor.execute.call_args.args
        self.assertIn("token, user_id, token_id, token_expires", sql)
        self.assertEqual(params, ("argon-hash", "user-1", "refresh-id", generate_tokens.return_value[3]))
        connection.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
