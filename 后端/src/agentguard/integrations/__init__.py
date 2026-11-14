"""Embed AgentGuard into your own FastAPI / Starlette apps (in-process)."""

from agentguard.integrations.fastapi import (
    guardrailed_user_text,
    include_gateway_router,
    register_agentguard_middleware,
)

__all__ = [
    "guardrailed_user_text",
    "register_agentguard_middleware",
    "include_gateway_router",
]
