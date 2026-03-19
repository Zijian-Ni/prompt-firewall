"""
OpenAI-compatible HTTP proxy with prompt-firewall scanning.

Runs a local HTTP server that transparently proxies requests to the OpenAI API
(or any OpenAI-compatible endpoint), scanning all messages before forwarding.

Usage::

    python -m prompt_firewall proxy --port 8080 --upstream https://api.openai.com

Then point your app at http://localhost:8080 instead of https://api.openai.com.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from prompt_firewall.config import FirewallConfig
from prompt_firewall.firewall import PromptFirewall

log = logging.getLogger(__name__)


def create_proxy_app(
    config: Optional[FirewallConfig] = None,
    upstream_url: str = "https://api.openai.com",
    scan_input: bool = True,
    scan_output: bool = True,
) -> FastAPI:
    """
    Create and return a FastAPI proxy application.

    Args:
        config: Firewall configuration.
        upstream_url: Base URL of the upstream LLM API.
        scan_input: Scan incoming messages before forwarding.
        scan_output: Scan outgoing responses before returning to caller.

    Returns:
        A FastAPI application.
    """
    firewall = PromptFirewall(config)
    app = FastAPI(title="prompt-firewall OpenAI Proxy", version="0.1.0")
    client = httpx.AsyncClient(base_url=upstream_url, timeout=120.0)

    def _block_response(result) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "type": "prompt_injection_detected",
                    "message": "Blocked by prompt-firewall",
                    "threat_level": result.threat_level,
                    "triggered": result.triggered_detectors,
                }
            },
        )

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(path: str, request: Request):
        body_bytes = await request.body()
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        # --- Input scanning ---
        if scan_input and body_bytes:
            try:
                body = json.loads(body_bytes)
                messages = body.get("messages", [])
                for msg in messages:
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        result = firewall.scan(content)
                        if result.blocked:
                            log.warning("Proxy blocked input [%s]", result.threat_level)
                            return _block_response(result)
            except json.JSONDecodeError:
                pass  # not a JSON body, pass through

        # --- Forward to upstream ---
        upstream_resp = await client.request(
            method=request.method,
            url=f"/{path}",
            headers=headers,
            content=body_bytes,
            params=dict(request.query_params),
        )

        # --- Output scanning ---
        if scan_output and "application/json" in upstream_resp.headers.get("content-type", ""):
            try:
                resp_body = upstream_resp.json()
                choices = resp_body.get("choices", [])
                for choice in choices:
                    content = choice.get("message", {}).get("content", "")
                    if isinstance(content, str):
                        result = firewall.scan(content)
                        if result.blocked:
                            log.warning("Proxy blocked output [%s]", result.threat_level)
                            return _block_response(result)
            except Exception:
                pass

        return StreamingResponse(
            content=iter([upstream_resp.content]),
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers),
        )

    return app
