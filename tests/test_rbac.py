import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import UserRole
from app.services.auth_service import AuthService
from app.schemas.user import UserCreate


@pytest.mark.asyncio
async def test_rbac_access_control(client: AsyncClient, test_user: dict, test_admin_user: dict):
    # Oddiy foydalanuvchini ro'yxatdan o'tkazish
    await client.post("/api/v1/auth/register", json=test_user)
    user_login = await client.post("/api/v1/auth/login", json=test_user)
    user_token = user_login.json()["access_token"]

    # Oddiy foydalanuvchi Admin paneliga kirishga urinsa -> 403 Forbidden
    res_forbidden = await client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res_forbidden.status_code == 403

    # Admin foydalanuvchini yaratish
    from tests.conftest import TestingSessionLocal
    async with TestingSessionLocal() as session:
        await AuthService.register_user(
            session,
            UserCreate(**test_admin_user),
            role=UserRole.ADMIN,
        )

    # Admin sifatida tizimga kirish
    admin_login = await client.post("/api/v1/auth/login", json=test_admin_user)
    admin_token = admin_login.json()["access_token"]

    # Admin muvaffaqiyatli foydalanuvchilar ro'yxatini oladi
    admin_res = await client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_res.status_code == 200
    users = admin_res.json()
    assert len(users) == 2


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    """Barcha javoblarda OWASP Security Headers borligini tekshirish"""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert "strict-transport-security" in response.headers
    assert "content-security-policy" in response.headers
