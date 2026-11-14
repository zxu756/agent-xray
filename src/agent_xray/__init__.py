"""agent-xray: Context token flamegraph & outbound privacy proxy for AI coding agents."""

from __future__ import annotations

__version__ = "0.2.0"

from .proxy import (
    ProxyConfig,
    RunningXRayProxy,
    XRayHTTPServer,
    XrayProxyServer,
    start_background_proxy,
)
from .store import TraceStore

__all__ = [
    "ProxyConfig",
    "RunningXRayProxy",
    "TraceStore",
    "XRayHTTPServer",
    "XrayProxyServer",
    "__version__",
    "start_background_proxy",
]
