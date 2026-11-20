from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.deps import require_roles
from app.models.user import User, UserRole
from app.schemas.user import UserResponse, UserUpdateRole

router = APIRouter(prefix="/admin", tags=["RBAC Admin"])


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="Barcha foydalanuvchilar ro'yxati (Faqat ADMIN uchun)",
)
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_roles([UserRole.ADMIN])),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Foydalanuvchi rolini o'zgartirish (Faqat ADMIN uchun)",
)
async def update_user_role(
    user_id: str,
    role_in: UserUpdateRole,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_roles([UserRole.ADMIN])),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Foydalanuvchi topilmadi",
        )

    user.role = role_in.role
    await db.commit()
    await db.refresh(user)
    return user
