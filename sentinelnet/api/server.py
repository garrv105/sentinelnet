"""
SentinelNet - REST API Server
================================
FastAPI-based REST API providing:
- Real-time status and statistics
- Incident querying
- Blocklist management
- Threat intelligence feed
- WebSocket for live event streaming

Security hardening:
- JWT Bearer token authentication (HS256)
- API Key header authentication (fallback)
- Rate limiting via slowapi (per-IP)
- Security headers middleware (HSTS, CSP, X-Frame-Options, etc.)
- CORS locked to configured origins in production
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import List, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import CurrentUser, TokenResponse, get_current_user, login_for_access_token, require_admin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter (per-IP)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

_ALLOWED_ORIGINS = os.getenv("SENTINELNET_CORS_ORIGINS", "*")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects standard security headers on every response.
    Does NOT break WebSocket upgrades.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        # Only add HSTS on HTTPS (avoids breaking HTTP dev servers)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none';"
        )
        return response


# ---------------------------------------------------------------------------
# Request/Response schemas
# ---------------------------------------------------------------------------


class IncidentFilter(BaseModel):
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    src_ip: Optional[str] = None
    limit: int = 50


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(engine_ref) -> FastAPI:
    """
    Create the FastAPI application.
    engine_ref: reference to the running SentinelEngine instance.
    """
    app = FastAPI(
        title="SentinelNet API",
        description=(
            "Real-time network threat detection and response API.\n\n"
            "**Authentication:** All endpoints (except `/auth/token`, `/api/v1/health`, and "
            "`/api/v1/status`) require authentication via:\n"
            "- `Authorization: Bearer <jwt>` — obtain from `POST /auth/token`\n"
            "- `X-API-Key: <key>` — configure via `SENTINELNET_API_KEYS` env var\n\n"
            "**Rate limits:** 200 requests/minute per IP (global), 10/minute on auth endpoints."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # --- Middleware stack (order matters: outermost = last in chain) ---

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS.split(",") if _ALLOWED_ORIGINS != "*" else ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    # Rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # WebSocket connection manager
    class ConnectionManager:
        def __init__(self):
            self._connections: List[WebSocket] = []
            self._lock = asyncio.Lock()

        async def connect(self, ws: WebSocket):
            await ws.accept()
            async with self._lock:
                self._connections.append(ws)

        async def disconnect(self, ws: WebSocket):
            async with self._lock:
                self._connections = [c for c in self._connections if c != ws]

        async def broadcast(self, message: str):
            async with self._lock:
                dead = []
                for ws in self._connections:
                    try:
                        await ws.send_text(message)
                    except Exception:
                        dead.append(ws)
                self._connections = [c for c in self._connections if c not in dead]

    manager = ConnectionManager()

    # -----------------------------------------------------------------------
    # Auth endpoints (public — no auth required)
    # -----------------------------------------------------------------------

    @app.post(
        "/auth/token",
        response_model=TokenResponse,
        tags=["auth"],
        summary="Obtain a JWT access token",
    )
    @limiter.limit("10/minute")
    async def token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
        """
        Exchange credentials for a JWT access token.

        Default dev credentials: `admin` / `changeme`
        Override via `SENTINELNET_ADMIN_USER` and `SENTINELNET_ADMIN_PASS_HASH` env vars.
        """
        return await login_for_access_token(form_data)

    @app.get("/api/v1/health", tags=["system"], summary="Health check (unauthenticated)")
    async def health():
        """Unauthenticated health probe for load balancers and orchestrators."""
        return {"status": "ok", "service": "sentinelnet"}

    # -----------------------------------------------------------------------
    # Protected endpoints — require auth
    # -----------------------------------------------------------------------

    @app.get("/api/v1/status", tags=["system"], summary="Runtime statistics")
    @limiter.limit("60/minute")
    async def get_status(
        request: Request,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """System health and runtime statistics."""
        return {
            "status": "running",
            "authenticated_as": _user.username,
            "auth_method": _user.auth_method,
            "capture_stats": engine_ref.capture_engine.get_stats(),
            "event_bus_stats": engine_ref.event_bus.get_stats(),
            "anomaly_stats": engine_ref.anomaly_engine.get_stats(),
            "active_flows": engine_ref.flow_tracker.get_active_count(),
        }

    @app.get("/api/v1/incidents", tags=["incidents"])
    @limiter.limit("60/minute")
    async def list_incidents(
        request: Request,
        severity: Optional[str] = Query(None),
        threat_type: Optional[str] = Query(None),
        src_ip: Optional[str] = Query(None),
        limit: int = Query(50, le=500, ge=1),
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Query historical threat incidents."""
        incidents = engine_ref.response_manager.query_incidents(
            severity=severity,
            threat_type=threat_type,
            src_ip=src_ip,
            limit=limit,
        )
        return {"count": len(incidents), "incidents": incidents}

    @app.get("/api/v1/blocklist", tags=["response"])
    @limiter.limit("60/minute")
    async def get_blocklist(
        request: Request,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """List currently blocked IP addresses."""
        return {"blocklist": engine_ref.response_manager.get_blocklist()}

    @app.post("/api/v1/block", tags=["response"])
    @limiter.limit("30/minute")
    async def block_ip(
        request: Request,
        block_req: BlockIPRequest,
        _user: CurrentUser = Depends(require_admin),  # admin only
    ):
        """
        Manually block an IP address.
        **Requires admin privileges.**
        """
        import uuid

        from ..core.event_bus import Severity, ThreatEvent

        event = ThreatEvent(
            event_id=str(uuid.uuid4()),
            source="ManualBlock",
            severity=Severity.HIGH,
            threat_type="manual_block",
            src_ip=block_req.ip,
            dst_ip="0.0.0.0",
            description=block_req.reason,
            score=1.0,
        )
        engine_ref.event_bus.publish(event)
        logger.info("Manual block issued by '%s' for IP %s", _user.username, block_req.ip)
        return {"status": "blocked", "ip": block_req.ip, "issued_by": _user.username}

    @app.delete("/api/v1/block/{ip}", tags=["response"])
    @limiter.limit("30/minute")
    async def unblock_ip(
        request: Request,
        ip: str,
        _user: CurrentUser = Depends(require_admin),  # admin only
    ):
        """
        Unblock a previously blocked IP address.
        **Requires admin privileges.**
        """
        for r in engine_ref.response_manager._responders:
            from ..responders.response_manager import IPBlocker

            if isinstance(r, IPBlocker):
                r.unblock(ip)
                logger.info("Unblock issued by '%s' for IP %s", _user.username, ip)
                return {"status": "unblocked", "ip": ip, "issued_by": _user.username}
        raise HTTPException(status_code=404, detail="IP blocker not enabled")

    @app.get("/api/v1/anomaly/profiles", tags=["detection"])
    @limiter.limit("30/minute")
    async def get_anomaly_profiles(
        request: Request,
        _user: CurrentUser = Depends(get_current_user),
    ):
        """Get per-IP behavioral profiles tracked by the anomaly detector."""
        return {"profiles": engine_ref.anomaly_engine.get_profiler_summary()}

    # -----------------------------------------------------------------------
    # WebSocket — authenticates via query param token or X-API-Key
    # -----------------------------------------------------------------------

    @app.websocket("/ws/events")
    async def websocket_events(
        websocket: WebSocket,
        token: Optional[str] = Query(None),
        api_key: Optional[str] = Query(None),
    ):
        """
        WebSocket stream for live threat events.

        Authenticate by providing one of:
        - Query param: `?token=<jwt>`
        - Query param: `?api_key=<key>`
        """
        import secrets

        from .auth import VALID_API_KEYS, decode_access_token

        # Auth check before accepting
        authenticated = False
        if token:
            try:
                decode_access_token(token)
                authenticated = True
            except HTTPException:
                pass
        if not authenticated and api_key and VALID_API_KEYS:
            import hashlib

            for vk in VALID_API_KEYS:
                if secrets.compare_digest(
                    hashlib.sha256(api_key.encode()).digest(),
                    hashlib.sha256(vk.encode()).digest(),
                ):
                    authenticated = True
                    break

        if not authenticated:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        await manager.connect(websocket)
        try:
            while True:
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            await manager.disconnect(websocket)

    # Hook into event bus to broadcast to WebSocket clients
    def _on_event(event):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(manager.broadcast(json.dumps(event.to_dict())), loop)
        except Exception as e:
            logger.debug("WebSocket broadcast error: %s", e)

    engine_ref.event_bus.subscribe("*", _on_event)

    return app
