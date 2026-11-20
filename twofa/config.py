import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

JWT_ACCESS_SECRET = os.getenv("JWT_ACCESS_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")
JWT_2FA_SECRET = os.getenv("JWT_2FA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")
PEPPER = os.getenv("PEPPER", "")
ISSUER = "IAM System"
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "IAM System")
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:4200")
WEBAUTHN_CHALLENGE_TTL = 300
FERNET_KEY = os.getenv("TOTP_ENCRYPTION_KEY")
fernet = Fernet(FERNET_KEY)
