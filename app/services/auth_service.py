import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_secure_token,
    hash_token,
)
from app.models.user import User, UserRole
from app.models.token import RefreshToken
from app.schemas.auth import TokenResponse
from app.schemas.user import UserCreate


class AuthService:
    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        result = await db.execute(select(User).where(User.email == email.lower()))
        return result.scalars().first()

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalars().first()

    @classmethod
    async def register_user(
        cls, db: AsyncSession, user_in: UserCreate, role: UserRole = UserRole.USER
    ) -> User:
        existing_user = await cls.get_user_by_email(db, user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ushbu elektron pochta allaqachon ro'yxatdan o'tgan",
            )

        new_user = User(
            email=user_in.email.lower(),
            hashed_password=hash_password(user_in.password),
            role=role,
            is_active=True,
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    @classmethod
    async def authenticate_user(
        cls, db: AsyncSession, email: str, password: str
    ) -> User:
        user = await cls.get_user_by_email(db, email)
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Elektron pochta yoki parol noto'g'ri",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Foydalanuvchi hisobi faol emas",
            )
        return user

    @classmethod
    async def issue_token_pair(
        cls, db: AsyncSession, user: User, family_id: Optional[str] = None
    ) -> TokenResponse:
        # Yangi login bo'lsa yangi oilaviy sessiya (family_id) yaratamiz
        active_family_id = family_id or str(uuid.uuid4())
        raw_refresh_token = generate_secure_token()
        token_hash = hash_token(raw_refresh_token)

        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        db_token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family_id=active_family_id,
            is_revoked=False,
            expires_at=expires_at,
        )
        db.add(db_token)
        await db.commit()

        access_token = create_access_token(
            subject=user.id,
            role=user.role.value,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @classmethod
    async def rotate_refresh_token(
        cls, db: AsyncSession, raw_refresh_token: str
    ) -> TokenResponse:
        """
        Refresh Token Rotation + Reuse Detection (OWASP Session Management)
        """
        token_hash = hash_token(raw_refresh_token)

        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalars().first()

        if not db_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Yaroqsiz yoki mavjud bo'lmagan refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 🚨 REUSE DETECTION (Eng muhim xavfsizlik mexanizmi)
        # Agar ilgari ishlatilgan yoki bekor qilingan token qayta taqdim etilsa:
        if db_token.is_revoked:
            # Token o'g'irlangan deb hisoblanadi va butun oilaviy sessiya bekor qilinadi!
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == db_token.family_id)
                .values(is_revoked=True)
            )
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Xavfsizlik signali: Token qayta ishlatilishi (reuse) aniqlandi! Barcha faol sessiyalar zudlik bilan bekor qilindi.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Token muddati o'tganligini tekshirish
        now = datetime.now(timezone.utc)
        token_exp = db_token.expires_at
        if token_exp.tzinfo is None:
            token_exp = token_exp.replace(tzinfo=timezone.utc)

        if token_exp < now:
            db_token.is_revoked = True
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token muddati tugagan. Qaytadan kiring.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Foydalanuvchini olish
        user = await cls.get_user_by_id(db, db_token.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Foydalanuvchi topilmadi yoki bloklangan",
            )

        # 1. Joriy ishlatilgan tokenni bekor qilamiz (Revoke)
        db_token.is_revoked = True
        await db.commit()

        # 2. Xuddi shu family_id bilan yangi token juftligini beramiz (Rotate)
        return await cls.issue_token_pair(db, user, family_id=db_token.family_id)

    @classmethod
    async def revoke_refresh_token(
        cls, db: AsyncSession, raw_refresh_token: str
    ) -> None:
        """Tizimdan chiqish (Logout) - sessiyani bekor qilish"""
        token_hash = hash_token(raw_refresh_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalars().first()
        if db_token:
            db_token.is_revoked = True
            await db.commit()
