"""Custom Swagger UI helpers for interactive docs."""

from __future__ import annotations

import json
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.openapi.docs import (
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import HTMLResponse

_SWAGGER_UI_INIT_MARKER = "const ui = SwaggerUIBundle({"
_SWAGGER_UI_SCRIPT_MARKER = "<!-- `SwaggerUIBundle` is now available on the page -->"


@dataclass(frozen=True)
class SwaggerDocsConfig:
    """Server-provided config consumed by the Swagger request interceptor."""

    csrf_cookie_name: str
    csrf_header_name: str
    bootstrap_csrf: bool
    csrf_bootstrap_path: str | None
    include_credentials: bool
    cookie_transport_header_name: str | None
    cookie_transport_header_value: str | None
    cookie_transport_paths: tuple[str, ...]
    protected_path_prefixes: tuple[str, ...]
    apply_csrf_to_unsafe_requests: bool

    def to_javascript(self) -> str:
        """Return the JSON payload consumed by the docs bootstrap script."""
        payload = {
            "csrfCookieName": self.csrf_cookie_name,
            "csrfHeaderName": self.csrf_header_name,
            "bootstrapCsrf": self.bootstrap_csrf,
            "csrfBootstrapPath": self.csrf_bootstrap_path,
            "includeCredentials": self.include_credentials,
            "cookieTransportHeaderName": self.cookie_transport_header_name,
            "cookieTransportHeaderValue": self.cookie_transport_header_value,
            "cookieTransportPaths": list(self.cookie_transport_paths),
            "protectedPathPrefixes": list(self.protected_path_prefixes),
            "applyCsrfToUnsafeRequests": self.apply_csrf_to_unsafe_requests,
        }
        return json.dumps(payload, sort_keys=True)


def _swagger_bootstrap_script(config: SwaggerDocsConfig) -> str:
    config_json = config.to_javascript()
    return f"""
<script>
window.__TWA_SWAGGER_DOCS_CONFIG__ = {config_json};
(function () {{
  const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
  const config = window.__TWA_SWAGGER_DOCS_CONFIG__;

  function toUrl(urlValue) {{
    try {{
      return new URL(urlValue, window.location.href);
    }} catch (error) {{
      return null;
    }}
  }}

  function normalizeHeaders(rawHeaders) {{
    if (!rawHeaders || typeof rawHeaders !== "object") {{
      return {{}};
    }}
    if (Array.isArray(rawHeaders)) {{
      return Object.fromEntries(rawHeaders);
    }}
    if (typeof Headers !== "undefined" && rawHeaders instanceof Headers) {{
      return Object.fromEntries(rawHeaders.entries());
    }}
    return {{ ...rawHeaders }};
  }}

  function getHeader(headers, name) {{
    const target = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {{
      if (key.toLowerCase() === target && typeof value === "string") {{
        return value;
      }}
    }}
    return "";
  }}

  function setHeader(headers, name, value) {{
    headers[name] = value;
  }}

  function readCookie(name) {{
    const prefix = `${{name}}=`;
    const match = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(prefix));
    return match ? decodeURIComponent(match.slice(prefix.length)) : "";
  }}

  function isProtectedPath(pathname) {{
    return config.protectedPathPrefixes.some(
      (prefix) => pathname === prefix || pathname.startsWith(prefix)
    );
  }}

  function shouldUseCookieTransport(headers, pathname, method) {{
    if (SAFE_HTTP_METHODS.has(method)) {{
      return false;
    }}
    if (!config.cookieTransportHeaderName || !config.cookieTransportHeaderValue) {{
      return false;
    }}
    if (!config.cookieTransportPaths.includes(pathname)) {{
      return false;
    }}

    const explicitTransport = getHeader(headers, config.cookieTransportHeaderName);
    if (explicitTransport) {{
      return (
        explicitTransport.toLowerCase() ===
        config.cookieTransportHeaderValue.toLowerCase()
      );
    }}
    return !getHeader(headers, "Authorization");
  }}

  async function ensureCsrfToken() {{
    let csrfToken = readCookie(config.csrfCookieName);
    if (csrfToken || !config.bootstrapCsrf) {{
      return csrfToken;
    }}

    const response = await fetch(config.csrfBootstrapPath, {{
      credentials: "include",
      headers: {{
        Accept: "application/json",
      }},
    }});
    if (!response.ok) {{
      throw new Error(
        `Unable to bootstrap CSRF token for Swagger UI requests (${{response.status}}).`
      );
    }}

    csrfToken = readCookie(config.csrfCookieName);
    if (csrfToken) {{
      return csrfToken;
    }}

    try {{
      const payload = await response.json();
      if (
        payload &&
        typeof payload.csrf_token === "string" &&
        payload.csrf_token.trim()
      ) {{
        return payload.csrf_token.trim();
      }}
    }} catch (error) {{
      console.warn("Unable to parse CSRF bootstrap response.", error);
    }}

    throw new Error(
      `CSRF bootstrap succeeded but no token was available for cookie "${{config.csrfCookieName}}".`
    );
  }}

  async function attachCsrf(headers) {{
    const csrfToken = await ensureCsrfToken();
    if (!csrfToken) {{
      throw new Error(
        `Missing CSRF cookie "${{config.csrfCookieName}}". Establish a browser session first.`
      );
    }}
    setHeader(headers, config.csrfHeaderName, csrfToken);
  }}

  window.__TWA_SWAGGER_REQUEST_INTERCEPTOR__ = async function (request) {{
    const url = toUrl(request.url);
    if (url === null || url.origin !== window.location.origin) {{
      return request;
    }}

    const method = String(request.method || "GET").toUpperCase();
    const headers = normalizeHeaders(request.headers);
    request.headers = headers;

    if (config.includeCredentials) {{
      request.credentials = "include";
    }}

    if (shouldUseCookieTransport(headers, url.pathname, method)) {{
      setHeader(
        headers,
        config.cookieTransportHeaderName,
        config.cookieTransportHeaderValue
      );
      await attachCsrf(headers);
      return request;
    }}

    if (config.applyCsrfToUnsafeRequests && !SAFE_HTTP_METHODS.has(method)) {{
      if (isProtectedPath(url.pathname)) {{
        await attachCsrf(headers);
      }}
    }}

    return request;
  }};
}})();
</script>
"""


def build_swagger_ui_html(
    *,
    openapi_url: str,
    title: str,
    swagger_docs_config: SwaggerDocsConfig,
    oauth2_redirect_url: str | None = None,
) -> HTMLResponse:
    """Render Swagger UI HTML with the custom request interceptor."""
    base_response = get_swagger_ui_html(
        openapi_url=openapi_url,
        title=title,
        oauth2_redirect_url=oauth2_redirect_url,
    )
    html = base_response.body.decode("utf-8")
    if _SWAGGER_UI_SCRIPT_MARKER not in html:
        raise RuntimeError("FastAPI Swagger UI HTML did not contain the expected script marker.")
    if _SWAGGER_UI_INIT_MARKER not in html:
        raise RuntimeError("FastAPI Swagger UI HTML did not contain the expected init marker.")

    html = html.replace(
        _SWAGGER_UI_SCRIPT_MARKER,
        f"{_swagger_bootstrap_script(swagger_docs_config)}\n{_SWAGGER_UI_SCRIPT_MARKER}",
        1,
    )
    html = html.replace(
        _SWAGGER_UI_INIT_MARKER,
        f"{_SWAGGER_UI_INIT_MARKER}\n        requestInterceptor: window.__TWA_SWAGGER_REQUEST_INTERCEPTOR__,",
        1,
    )

    headers = {
        key: value
        for key, value in base_response.headers.items()
        if key.lower() != "content-length"
    }
    return HTMLResponse(content=html, status_code=base_response.status_code, headers=headers)


def register_swagger_ui_docs(
    app: FastAPI,
    *,
    openapi_url: str,
    title: str,
    swagger_docs_config: SwaggerDocsConfig,
) -> None:
    """Register the custom Swagger UI endpoints on the application."""

    async def swagger_ui_html() -> HTMLResponse:
        return build_swagger_ui_html(
            openapi_url=openapi_url,
            title=title,
            swagger_docs_config=swagger_docs_config,
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        )

    app.add_api_route("/docs", swagger_ui_html, include_in_schema=False)

    if app.swagger_ui_oauth2_redirect_url:
        app.add_api_route(
            app.swagger_ui_oauth2_redirect_url,
            get_swagger_ui_oauth2_redirect_html,
            include_in_schema=False,
        )
