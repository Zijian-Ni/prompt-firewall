"""
FastAPI integration example.

Run with: uvicorn fastapi_integration:app --reload
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

from prompt_firewall import PromptFirewall, PromptInjectionError, FirewallConfig
from prompt_firewall.middleware.fastapi import PromptFirewallMiddleware

# --- Option A: Middleware (automatic, transparent) ---
app = FastAPI(title="My LLM App with Firewall")

# Add middleware — scans all POST /v1/chat/completions requests
app.add_middleware(
    PromptFirewallMiddleware,
    scan_paths=["/v1/chat/completions", "/api/chat"],
)


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]


@app.post("/v1/chat/completions")
async def chat(req: ChatRequest):
    # If we reach here, the middleware has already cleared all messages
    return {
        "choices": [
            {"message": {"role": "assistant", "content": "Safe response!"}}
        ]
    }


# --- Option B: Manual scanning in route handlers ---
fw = PromptFirewall(FirewallConfig.strict())


@app.post("/api/chat")
async def chat_manual(req: ChatRequest):
    for msg in req.messages:
        if msg.role == "user":
            result = fw.scan(msg.content)
            if result.blocked:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "Prompt blocked",
                        "threat_level": result.threat_level,
                        "detectors": result.triggered_detectors,
                    },
                )

    return {"choices": [{"message": {"role": "assistant", "content": "Safe!"}}]}


# Health check
@app.get("/health")
async def health():
    return {"status": "ok", "firewall": "active"}
