"""SafeContain AI Enterprise Security Middleware & Input Sanitization.

Enforces HTTP security response headers, correlation IDs, and Cypher/SQL injection protection.
"""

import re
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Prohibited patterns for raw graph queries to prevent Cypher injection
CYPHER_INJECTION_PATTERN = re.compile(
    r"(\bMATCH\b|\bMERGE\b|\bDELETE\b|\bDETACH\b|\bCREATE\b|\bDROP\b|\bSET\b|\bCALL\b|\bLOAD\s+CSV\b|--|//|\/\*)",
    re.IGNORECASE
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces enterprise security headers across all API responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID") or f"req-{uuid.uuid4().hex[:12]}"
        response: Response = await call_next(request)

        # Standard OWASP / CERT-In Recommended Response Headers
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


def sanitize_graph_query_input(user_input: str) -> str:
    """Sanitizes user-supplied string search parameters against Cypher injection."""
    if not user_input:
        return ""
    if CYPHER_INJECTION_PATTERN.search(user_input):
        raise ValueError(f"Prohibited pattern or injection sequence detected in input: '{user_input}'")
    # Escape quotes and backslashes
    return user_input.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
