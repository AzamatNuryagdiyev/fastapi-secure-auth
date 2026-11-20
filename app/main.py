from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import engine, Base
from app.core.middleware import SecurityHeadersMiddleware
from app.core.rate_limit import limiter
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dastur ishga tushganda jadvallarni yaratish (Alembic ishlatilmagan holatlarda)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Dastur to'xtaganda ulanishlarni yopish
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="OWASP tavsiyalari asosida tuzilgan Production-Ready Secure FastAPI Auth Boilerplate",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# 1. Rate Limiting sozlamasi
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 2. Xavfsizlik HTTP Sarlavhalari Middleware (OWASP Security Headers)
app.add_middleware(SecurityHeadersMiddleware)

# 3. CORS Middleware (Xavfsiz domenlar)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# 4. Routerlarni ulash
app.include_router(auth_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
    }
