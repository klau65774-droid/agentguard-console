"""Response headers for guardrail and gateway wall-clock timing."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from agentguard.config import settings


class GuardrailLatencyHeaderMiddleware(BaseHTTPMiddleware):
    """Expose recorded guardrail timings, falling back to time until response headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        if not settings.expose_guardrail_latency_header:
            return response

        parts: list[str] = []
        input_ms = getattr(request.state, "agentguard_input_guardrails_ms", None)
        output_ms = getattr(request.state, "agentguard_output_validation_ms", None)
        if input_ms is not None:
            parts.append(f"input_guardrails={float(input_ms):.3f}")
        if output_ms is not None:
            parts.append(f"output_validation={float(output_ms):.3f}")
        if input_ms is None and output_ms is None:
            total_ms = (time.perf_counter() - start) * 1000.0
            parts.append(f"gateway={total_ms:.3f}")
        response.headers["X-AgentGuard-Latency-Ms"] = ";".join(parts)
        return response
