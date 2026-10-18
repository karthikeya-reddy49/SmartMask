"""FastAPI application factory and process lifecycle."""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ..audit.repository import AuditRepository
from ..auth.auth_service import AuthService
from ..auth.token_service import TokenService
from ..auth.user_repository import UserRepository
from ..config import AppConfig
from ..database.connection import DatabaseManager
from ..database.registry import DatabaseRegistry
from ..scanner.metadata_repository import MetadataRepository
from .routes import router

logger = logging.getLogger("smartmask.api")


def create_app(config: AppConfig | None = None) -> FastAPI:
    config = config or AppConfig.from_env()
    if "*" in config.cors_origins:
        raise ValueError("Wildcard CORS is not supported; configure explicit origins.")
    if config.api_docs_enabled:
        docs_url, redoc_url, openapi_url = "/docs", "/redoc", "/openapi.json"
    else:
        docs_url = redoc_url = openapi_url = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Validate the secret only when the API runtime starts; CLI commands do
        # not require JWT configuration.
        token_service = TokenService(config)
        registry = DatabaseRegistry(config)
        # This manager owns the control store only. Source access is exclusively
        # through configured read-only adapters in the registry.
        manager = DatabaseManager("sqlite://", config.control_db_url)
        manager.initialize()
        MetadataRepository(manager).initialize_schema()
        app.state.config = config
        app.state.manager = manager
        app.state.registry = registry
        app.state.users = UserRepository(manager)
        app.state.auth_service = AuthService(app.state.users, token_service, AuditRepository(manager))
        app.state.login_attempts = {}
        import threading
        app.state.login_lock = threading.Lock()
        try:
            yield
        finally:
            registry.dispose()
            manager.dispose()

    app = FastAPI(title="Smart Data Masking API", version="2.0.0",
                  docs_url=docs_url, redoc_url=redoc_url, openapi_url=openapi_url,
                  # API errors always use the sanitized handlers below. A
                  # staging/test environment must not turn on traceback bodies.
                  debug=False, lifespan=lifespan)
    app.include_router(router, prefix="/api/v1")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > 1_000_000:
            return JSONResponse(status_code=413, content={"error": {
                "code": "REQUEST_TOO_LARGE", "message": "Request body is too large."}})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    if config.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(config.cors_origins),
            allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"])
    if config.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.trusted_hosts))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"error": {
            "code": "INVALID_REQUEST", "message": "Request validation failed."}})

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {
            "code": "HTTP_ERROR", "message": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code,
                            content={"error": detail}, headers=exc.headers)

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        logger.error("Unhandled API error; request_id=%s", getattr(request.state, "request_id", "unknown"))
        return JSONResponse(status_code=500, content={"error": {
            "code": "INTERNAL_ERROR", "message": "The request could not be completed."},
            "request_id": getattr(request.state, "request_id", None)})

    return app


def run() -> None:
    import uvicorn
    config = AppConfig.from_env()
    uvicorn.run("smartmask.api.app:app", host=config.api_host, port=config.api_port,
                reload=config.api_environment == "development", log_level=config.log_level.lower())


app = create_app()
