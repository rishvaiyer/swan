"""Shared loopback HTTP boundary for local review services."""

from urllib.parse import urlsplit

from fastapi.responses import JSONResponse


def install_local_boundary(app, max_request_bytes):
    @app.middleware("http")
    async def local_boundary(request, call_next):
        authority = request.headers.get("host", "")
        try:
            host = urlsplit("//" + authority)
            valid_host = (
                host.hostname in {"127.0.0.1", "localhost"}
                and host.username is None
                and host.password is None
                and not host.path
                and not host.query
                and not host.fragment
                and (host.port is None or 1 <= host.port <= 65535)
            )
        except ValueError:
            valid_host = False
        if not valid_host:
            return JSONResponse({"detail": "Loopback host required."}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                valid_origin = (
                    parsed.netloc == authority
                    and parsed.scheme == request.url.scheme
                    and not parsed.path
                    and not parsed.query
                    and not parsed.fragment
                )
            except ValueError:
                valid_origin = False
            if not valid_origin:
                return JSONResponse(
                    {"detail": "Cross-origin requests are not accepted."},
                    status_code=403,
                )
        if request.method in {"POST", "PUT", "PATCH"}:
            value = request.headers.get("content-length", "")
            if (
                not value
                or len(value) > 10
                or not value.isascii()
                or not value.isdecimal()
            ):
                return JSONResponse(
                    {"detail": "A bounded Content-Length is required."}, status_code=411
                )
            if int(value) > max_request_bytes:
                return JSONResponse(
                    {"detail": "Request body is too large."}, status_code=413
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response
