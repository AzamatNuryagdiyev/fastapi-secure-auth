import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient, test_user: dict):
    response = await client.post("/api/v1/auth/register", json=test_user)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == test_user["email"].lower()
    assert "id" in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_weak_password(client: AsyncClient):
    # Katta harf va maxsus belgisi yo'q parol
    weak_user = {
        "email": "weak@example.com",
        "password": "simplepassword",
    }
    response = await client.post("/api/v1/auth/register", json=weak_user)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient, test_user: dict):
    # Birinchi marta ro'yxatdan o'tish
    res1 = await client.post("/api/v1/auth/register", json=test_user)
    assert res1.status_code == 201

    # Ikkinchi marta xuddi shu email bilan urinish
    res2 = await client.post("/api/v1/auth/register", json=test_user)
    assert res2.status_code == 409


@pytest.mark.asyncio
async def test_login_success_and_me(client: AsyncClient, test_user: dict):
    # Ro'yxatdan o'tish
    await client.post("/api/v1/auth/register", json=test_user)

    # Login qilish
    login_res = await client.post("/api/v1/auth/login", json=test_user)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"

    # /auth/me tekshirish
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    me_res = await client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == test_user["email"].lower()


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient, test_user: dict):
    await client.post("/api/v1/auth/register", json=test_user)

    wrong_login = {
        "email": test_user["email"],
        "password": "WrongPassword123!",
    }
    res = await client.post("/api/v1/auth/login", json=wrong_login)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_detection(
    client: AsyncClient, test_user: dict
):
    """
    OWASP Token Rotation & Reuse Detection test:
    1. Tizimga kirish -> Refresh Token A
    2. Refresh A orqali yangilash -> Yangi Refresh Token B olinadi (A bekor qilinadi)
    3. Hujumchi Refresh Token A ni qayta ishlatishga uringanda -> REUSE aniqlanadi!
    4. Natijada B ham bekor qilinadi va barcha sessiyalar yopiladi!
    """
    await client.post("/api/v1/auth/register", json=test_user)

    # 1. Login
    login_res = await client.post("/api/v1/auth/login", json=test_user)
    refresh_token_a = login_res.json()["refresh_token"]

    # 2. To'g'ri Rotation (A -> B)
    rotate_res = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token_a}
    )
    assert rotate_res.status_code == 200
    refresh_token_b = rotate_res.json()["refresh_token"]
    assert refresh_token_b != refresh_token_a

    # 3. Bekor qilingan tokenni qayta ishlatish (REUSE ATTACK)
    reuse_res = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token_a}
    )
    assert reuse_res.status_code == 401
    assert "reuse" in reuse_res.json()["detail"].lower()

    # 4. Endi Token B ham bekor bo'lganini tekshirish (chunki sessiya o'g'irlangan deb hisoblandi)
    b_res = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token_b}
    )
    assert b_res.status_code == 401


@pytest.mark.asyncio
async def test_logout(client: AsyncClient, test_user: dict):
    await client.post("/api/v1/auth/register", json=test_user)
    login_res = await client.post("/api/v1/auth/login", json=test_user)
    refresh_token = login_res.json()["refresh_token"]

    # Logout
    logout_res = await client.post(
        "/api/v1/auth/logout", json={"refresh_token": refresh_token}
    )
    assert logout_res.status_code == 200

    # Chiqilgandan so'ng tokendan foydalanib bo'lmasligi kerak
    refresh_res = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_res.status_code == 401
