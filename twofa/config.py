import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

JWT_ACCESS_SECRET = os.getenv("JWT_ACCESS_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")
JWT_2FA_SECRET = os.getenv("JWT_2FA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")
ISSUER = "IAM System"
FERNET_KEY = os.getenv("TOTP_ENCRYPTION_KEY")
fernet = Fernet(FERNET_KEY)
