"""Route modules included by ``web.app``.

Each module exposes one ``router``; ``web.app`` imports it under an explicit
name and calls ``include_router`` before the permission registry is first
built.
"""
from web.routers.auth import router as auth_router
from web.routers.buckets import router as buckets_router
from web.routers.config import router as config_router
from web.routers.public import router as public_router
from web.routers.telegram import router as telegram_router
from web.routers.users import router as users_router

__all__ = ["auth_router", "buckets_router", "config_router", "public_router",
           "telegram_router", "users_router"]
