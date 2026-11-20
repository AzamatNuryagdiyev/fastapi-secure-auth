import re
from datetime import datetime
from typing import Annotated
from pydantic import BaseModel, Field, field_validator, ConfigDict, BeforeValidator
from app.models.user import UserRole

# Resilient EmailStr validator (ishlaydi email-validator o'rnatilgan yoki o'rnatilmagan holatda ham)
EMAIL_REGEX = re.compile(r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$")


def validate_email_format(v: str) -> str:
    if not isinstance(v, str) or not EMAIL_REGEX.match(v):
        raise ValueError("Yaroqsiz elektron pochta manzili formati")
    return v.lower().strip()


try:
    import email_validator
    from pydantic import EmailStr as PydanticEmailStr
    EmailStr = PydanticEmailStr
except (ImportError, Exception):
    EmailStr = Annotated[str, BeforeValidator(validate_email_format)]


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Parol kamida 8 ta belgidan iborat bo'lishi kerak")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Parolda kamida 1 ta katta harf (A-Z) bo'lishi shart")
        if not re.search(r"[a-z]", v):
            raise ValueError("Parolda kamida 1 ta kichik harf (a-z) bo'lishi shart")
        if not re.search(r"\d", v):
            raise ValueError("Parolda kamida 1 ta raqam (0-9) bo'lishi shart")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Parolda kamida 1 ta maxsus belgi (!@#$%^&*...) bo'lishi shart")
        return v


class UserResponse(UserBase):
    id: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdateRole(BaseModel):
    role: UserRole
