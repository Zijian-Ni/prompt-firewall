"""
FastAPI middleware for prompt-firewall.

Drop-in middleware that scans the ``messages`` field of OpenAI-style request
bodies and blocks requests that contain threats.

Usage::

    from fastapi import FastAPI
    from prompt_firewall.middleware.fastapi import PromptFirewallMiddleware

    app = FastAPI()
    app.add_middleware(PromptFirewallMiddleware)
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from prompt_firewall.config import FirewallConfig
from prompt_firewall.firewall import PromptFirewall

log = logging.getLogger(__name__)


class PromptFirewallMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that intercepts chat-completion requests
    and scans the ``messages[].content`` fields for threats.

    Args:
        app: The ASGI application.
        config: Optional :class:`~prompt_firewall.config.FirewallConfig`.
        scan_paths: Paths to intercept (default: ``["/v1/chat/completions"]``).
        block_status_code: HTTP status code when a threat is detected (default: 400).
    """

    def __init__(
        self,
        app,
        config: Optional[FirewallConfig] = None,
        scan_paths: Optional[list[str]] = None,
        block_status_code: int = 400,
    ) -> None:
        super().__init__(app)
        self._firewall = PromptFirewall(config)
        self._scan_paths = set(scan_paths or ["/v1/chat/completions"])
        self._block_status_code = block_status_code

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path not in self._scan_paths:
            return await call_next(request)

        # Read body
        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError:
            return await call_next(request)

        # Extract messages
        messages = body.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue
            result = self._firewall.scan(content)
            if result.blocked:
                log.warning(
                    "PromptFirewallMiddleware blocked request [%s]: %s",
                    result.threat_level,
                    result.triggered_detectors,
                )
                return JSONResponse(
                    status_code=self._block_status_code,
                    content={
                        "error": {
                            "type": "prompt_injection_detected",
                            "message": "Request blocked by prompt-firewall",
                            "threat_level": result.threat_level,
                            "triggered": result.triggered_detectors,
                        }
                    },
                )

        return await call_next(request)
