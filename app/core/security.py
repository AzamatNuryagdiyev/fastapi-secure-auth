import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from app.config import settings

# --- Password Hashing (Argon2id with secure Scrypt fallback) ---
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
    )

    def hash_password(password: str) -> str:
        """Argon2id algoritmi yordamida parolni xeshlash"""
        return _hasher.hash(password)

    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Argon2id xeshini tekshirish"""
        try:
            return _hasher.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

except ImportError:
    # Argon2 kutubxonasi bo'lmaganda OWASP tavsiya etgan xotira-og'ir scrypt algoritmi
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            maxmem=0,
        )
        return f"scrypt${salt.hex()}${key.hex()}"

    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            if not hashed_password.startswith("scrypt$"):
                return False
            _, salt_hex, key_hex = hashed_password.split("$")
            salt = bytes.fromhex(salt_hex)
            expected_key = bytes.fromhex(key_hex)
            computed_key = hashlib.scrypt(
                plain_password.encode("utf-8"),
                salt=salt,
                n=16384,
                r=8,
                p=1,
                maxmem=0,
            )
            return secrets.compare_digest(expected_key, computed_key)
        except Exception:
            return False


# --- Token Management ---

def hash_token(token: str) -> str:
    """Tokenning SHA-256 xeshini hisoblash (ma'lumotlar bazasida xom tokenni saqlamaslik uchun)"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_secure_token() -> str:
    """Kriptografik jihatdan xavfsiz tasodifiy string"""
    return secrets.token_urlsafe(48)


def create_access_token(
    subject: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Qisqa muddatli JWT Access Token yaratish"""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": now,
        "nbf": now,
        "type": "access",
    }
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """JWT Access Tokenni tekshirish va dekodlash"""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "type"]},
        )
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None
