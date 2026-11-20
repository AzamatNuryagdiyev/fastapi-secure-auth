from typing import List
from fastapi import HTTPException, status
from app.models.user import User, UserRole

ROLE_HIERARCHY = {
    UserRole.USER: 1,
    UserRole.MODERATOR: 2,
    UserRole.ADMIN: 3,
}


def check_role_permission(user: User, allowed_roles: List[UserRole]) -> bool:
    """Foydalanuvchi roli ruxsat etilgan rollar ro'yxatida borligini tekshiradi"""
    return user.role in allowed_roles


def check_minimum_role(user: User, minimum_role: UserRole) -> bool:
    """Ierarxiya bo'yicha minimal talab qilinadigan rolni tekshirish"""
    user_level = ROLE_HIERARCHY.get(user.role, 0)
    required_level = ROLE_HIERARCHY.get(minimum_role, 0)
    return user_level >= required_level
