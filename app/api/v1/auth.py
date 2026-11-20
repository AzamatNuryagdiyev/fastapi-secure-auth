from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.rate_limit import limiter
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    MessageResponse,
)
from app.schemas.user import UserCreate, UserResponse
from app.models.user import User
from app.services.auth_service import AuthService
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Yangi foydalanuvchini ro'yxatdan o'tkazish",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Parol mustahkamligi tekshiriladi (kamida 8 belgi, Katta/kichik harf, raqam va maxsus belgi).
    Parol Argon2id orqali xeshlanadi.
    """
    return await AuthService.register_user(db, user_in)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Tizimga kirish va tokenlar juftligini olish",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    login_in: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Foydalanuvchi autentifikatsiya qilinadi.
    Qisqa muddatli Access Token va xavfsiz Refresh Token beriladi.
    """
    user = await AuthService.authenticate_user(db, login_in.email, login_in.password)
    return await AuthService.issue_token_pair(db, user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh Token Rotation (Reuse Detection bilan)",
)
@limiter.limit("20/minute")
async def refresh_token(
    request: Request,
    refresh_in: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Eski refresh tokenni bekor qiladi va yangi juftlik chiqaradi.
    Agar ilgari bekor qilingan token qayta ishlatilsa, sessiya o'g'irlangan deb
    baholanadi va barcha oilaviy tokenlar bekor qilinadi!
    """
    return await AuthService.rotate_refresh_token(db, refresh_in.refresh_token)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Tizimdan chiqish (Sessiyani bekor qilish)",
)
async def logout(
    refresh_in: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    await AuthService.revoke_refresh_token(db, refresh_in.refresh_token)
    return MessageResponse(message="Muvaffaqiyatli tizimdan chiqildi")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Joriy tizimga kirgan foydalanuvchi ma'lumotlari",
)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
