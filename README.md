# 🔐 FastAPI Secure Auth Boilerplate

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-005571.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.7%2B-e92063.svg)](https://docs.pydantic.dev/)
[![Argon2id](https://img.shields.io/badge/Password%20Hashing-Argon2id-critical.svg)](https://en.wikipedia.org/wiki/Argon2)
[![OWASP Compliance](https://img.shields.io/badge/OWASP-ASVS%20Level%202-brightgreen.svg)](https://owasp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**FastAPI Secure Auth Boilerplate** — ishlab chiqarish (production) muhiti va xalqaro **OWASP** xavfsizlik standartlariga to‘liq javob beruvchi zamonaviy autentifikatsiya va avtorizatsiya backend shabloni.

Ko‘pchilik dasturchilar har safar qaytadan yozishga erinadigan xavfsizlik mexanizmlari (Argon2id, Refresh Token Rotation, Reuse Detection, RBAC, Rate Limiting va Security Headers) barchasi bitta toza arxitekturada jamlangan.

---

## 🛡️ Xavfsizlik Arxitekturasi & Imkoniyatlar

| Xususiyat | Tavsif & Standart |
| :--- | :--- |
| **Parol Xeshlash** | **Argon2id** (Parol xeshlash bo‘yicha dunyo chempioni, GPU/ASIC hujumlariga qarshi memory-hard algoritm). |
| **Parol Siyosati** | Kamida 8 ta belgi, 1 ta katta harf, 1 ta kichik harf, 1 ta raqam va maxsus belgi talab qilinadi. |
| **Access Token** | Qisqa muddatli JWT (15 daqiqa), stateless va minimal claimlar bilan. |
| **Refresh Token Rotation** | Har safar yangilanishda eski refresh token bekor qilinadi va yangisi chiqariladi. |
| **Reuse Detection** | **Eng muhim OWASP mexanizmi**: Agar bekor qilingan refresh token qayta ishlatilsa, tizim token o‘g‘irlanganini payqaydi va **barcha sessiyalarni zudlik bilan bekor qiladi**. |
| **Hashed Tokens in DB** | Refresh tokenlar bazada xom holda emas, SHA-256 xesh ko‘rinishida saqlanadi (baza buzilsa ham tokenlar sizmaydi). |
| **RBAC (Role-Based Access)** | Ierarxik rollar tizimi: `USER`, `MODERATOR`, `ADMIN`. |
| **Rate Limiting** | `Slowapi` orqali `/login` va `/register` endpointlariga Brute-force va DoS hujumlarini cheklash. |
| **Security Headers** | HSTS, CSP, X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy. |
| **SQLAlchemy 2.0 Async** | `asyncpg` orqali yuqori unumdorlikdagi asinxron PostgreSQL drayveri. |

---

## 📁 Loyiha Strukturasi

Clean Architecture va Domain-Driven tamoyillariga asoslangan struktura:

```plaintext
fastapi-secure-auth/
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI testi
├── app/
│   ├── __init__.py
│   ├── config.py              # Pydantic Settings v2 (.env boshqaruvi)
│   ├── database.py            # Asinxron SQLAlchemy dvigateli va sessiyalar
│   ├── main.py                # FastAPI app, middlewarelar va routerlar
│   ├── core/                  # Xavfsizlik yadrosi
│   │   ├── security.py        # Argon2id xeshlash, JWT kodlash va token generator
│   │   ├── rbac.py            # Rollar ierarxiyasi va ruxsatlar mantiqi
│   │   ├── rate_limit.py      # Slowapi sozlamalari
│   │   └── middleware.py      # OWASP HTTP sarlavhalari middleware
│   ├── models/                # Ma'lumotlar bazasi modellari
│   │   ├── user.py            # Foydalanuvchi modeli va UserRole enum
│   │   └── token.py           # RefreshToken modeli (family_id, reuse tracking)
│   ├── schemas/               # Pydantic v2 DTO va validatsiya
│   │   ├── auth.py            # Login, TokenResponse, Refresh sxemalari
│   │   └── user.py            # Parol kuchi tekshiruvi va UserResponse
│   ├── services/              # Biznes mantiq
│   │   └── auth_service.py    # Ro'yxatdan o'tish, login, rotation va reuse detection
│   └── api/
│       ├── deps.py            # FastAPI dependencies (get_current_user, require_roles)
│       └── v1/
│           ├── auth.py        # /register, /login, /refresh, /logout, /me
│           └── users.py       # Himoyalangan admin boshqaruvi
├── tests/
│   ├── conftest.py            # Asinxron test client va in-memory DB fixture
│   ├── test_auth.py           # Autentifikatsiya va Reuse Detection unit testlari
│   └── test_rbac.py           # Ruxsatlar va xavfsizlik sarlavhalari testlari
├── docker-compose.yml         # FastAPI + PostgreSQL 16
├── Dockerfile                 # Multi-stage xavfsiz Docker konteyneri
├── pyproject.toml             # Zamonaviy paket boshqaruvi
├── .env.example               # Muhit o'zgaruvchilari namunasi
└── README.md
```

---

## 🚀 O‘rnatish va Ishga Tushirish

### 1. Repozitoriyani klonlash:
```bash
git clone https://github.com/AzamatNuryagdiyev/fastapi-secure-auth.git
cd fastapi-secure-auth
```

### 2. Virtual muhitni yoqish:
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Paketlarni o‘rnatish:
```bash
pip install -e ".[dev]"
```

### 4. Konfiguratsiya:
`.env.example` faylidan nusxa olib `.env` yarating:
```bash
copy .env.example .env   # Windows
cp .env.example .env     # Linux/macOS
```

### 5. Serverni ishga tushirish:
```bash
uvicorn app.main:app --reload
```
API Hujjatlari (Swagger UI): **`http://localhost:8000/docs`**

---

## 🐳 Docker Orqali Ishga Tushirish

FastAPI va PostgreSQL birgalikda birgina buyruq bilan ko‘tariladi:

```bash
docker compose up --build -d
```

---

## 🧪 Testlarni Ishga Tushirish

Testlar alohida in-memory asinxron SQLite bazasida ishlaydi (PostgreSQL o‘rnatilmagan bo‘lsa ham testlar to‘liq o‘tadi):

```bash
pytest
```

---

## 📡 API Endpointlar Xaritasi

### 🔐 Autentifikatsiya (`/api/v1/auth`)
- `POST /register` — Yangi hisob ochish (Parol kuchi tekshiruvi + Rate limit).
- `POST /login` — Kirish (Access Token + Refresh Token).
- `POST /refresh` — Tokenlarni yangilash (**Reuse Detection** bilan).
- `POST /logout` — Sessiyani bekor qilish.
- `GET /me` — Joriy foydalanuvchi ma'lumotlari.

### 🛡️ RBAC Admin (`/api/v1/admin`)
- `GET /users` — Barcha foydalanuvchilar (Faqat `ADMIN` roli uchun).
- `PATCH /users/{id}/role` — Rolni o‘zgartirish (Faqat `ADMIN` roli uchun).

---

## 📄 Litsenziya

Loyiha [MIT](LICENSE) litsenziyasi ostida ochiq taqdim etiladi.
