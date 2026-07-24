import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx
import uvicorn

app = FastAPI(title="Agent Guardrail Endpoint")

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-b2405bda82").resolve()
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

# Keywords or patterns indicating metadata/internal network access
INTERNAL_PATTERNS = [
    r"169\.254\.",
    r"127\.",
    r"localhost",
    r"0\.0\.0\.0",
    r"10\.",
    r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"192\.168\.",
    r"::1",
    r"fe80:",
    r"metadata",
]


def is_path_safe(requested_path: str) -> bool:
    """Verifies if the canonical target path remains inside the sandbox root."""
    try:
        # Resolve path handling both absolute and relative inputs
        raw_path = Path(requested_path)
        if raw_path.is_absolute():
            resolved_target = raw_path.resolve()
        else:
            resolved_target = (SANDBOX_ROOT / raw_path).resolve()

        # Target must be strictly equal to or inside SANDBOX_ROOT
        return resolved_target == SANDBOX_ROOT or SANDBOX_ROOT in resolved_target.parents
    except Exception:
        return False


def contains_internal_target(value: str) -> bool:
    """Checks string or parameter for references to internal/metadata endpoints."""
    decoded = unquote(value).lower()

    for pattern in INTERNAL_PATTERNS:
        if re.search(pattern, decoded):
            return True

    # Check if string parses as an IP address
    try:
        ip = ipaddress.ip_address(decoded)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    except ValueError:
        pass

    return False


def is_url_safe(raw_url: str) -> bool:
    """Validates host authority and checks query parameters for SSRF redirects."""
    try:
        parsed = urlparse(raw_url)

        # Enforce scheme
        if parsed.scheme not in ("http", "https"):
            return False

        # Check hostname strictly against allowlist
        hostname = (parsed.hostname or "").lower()
        if hostname not in ALLOWED_HOSTS:
            return False

        # Block userinfo confusion (e.g. http://allowed.com@169.254.169.254)
        if parsed.username or parsed.password:
            return False

        # Check query parameters for open-redirect SSRF parameters
        query_params = parse_qs(parsed.query)
        for param_values in query_params.values():
            for val in param_values:
                if contains_internal_target(val):
                    return False

        return True
    except Exception:
        return False


async def execute_read_file(path_str: str) -> str:
    """Executes read_file tool safely."""
    raw_path = Path(path_str)
    full_path = raw_path if raw_path.is_absolute() else SANDBOX_ROOT / raw_path
    
    if not full_path.exists() or not full_path.is_file():
        raise FileNotFoundError(f"File not found: {path_str}")

    return full_path.read_text(encoding="utf-8", errors="replace")


async def execute_fetch_url(url_str: str) -> str:
    """Executes fetch_url tool safely with redirects disabled."""
    async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
        response = await client.get(url_str)
        # Block if a redirect attempts to steer to an unauthorized endpoint
        if response.is_redirect:
            redirect_loc = response.headers.get("location", "")
            if redirect_loc and not is_url_safe(redirect_loc):
                raise PermissionError("Redirect to unauthorized or internal host blocked.")
        return response.text


@app.post("/")
async def guardrail_endpoint(request: Request):
    """Main HTTP entrypoint for tool calls."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"action": "block", "reason": "Invalid JSON format", "result": None}
        )

    tool = data.get("tool")
    arguments = data.get("arguments", {})

    # 1. Handle read_file
    if tool == "read_file":
        path = arguments.get("path")
        if not path or not is_path_safe(path):
            return JSONResponse({
                "action": "block",
                "reason": "Path traversal or unauthorized directory access attempt.",
                "result": None
            })
        
        try:
            content = await execute_read_file(path)
            return JSONResponse({
                "action": "allow",
                "reason": "Path is within allowed sandbox root.",
                "result": content
            })
        except Exception as e:
            return JSONResponse({
                "action": "allow",
                "reason": "Allowed by guardrail, but tool execution failed.",
                "result": str(e)
            })

    # 2. Handle fetch_url
    elif tool == "fetch_url":
        url = arguments.get("url")
        if not url or not is_url_safe(url):
            return JSONResponse({
                "action": "block",
                "reason": "URL destination or embedded target is not permitted.",
                "result": None
            })

        try:
            content = await execute_fetch_url(url)
            return JSONResponse({
                "action": "allow",
                "reason": "Host is in allowed list and query parameters are safe.",
                "result": content
            })
        except Exception as e:
            return JSONResponse({
                "action": "allow",
                "reason": "Allowed by guardrail, but network fetch failed.",
                "result": str(e)
            })

    # 3. Fallback for unrecognized tools
    return JSONResponse({
        "action": "block",
        "reason": f"Tool '{tool}' is unrecognized.",
        "result": None
    })


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)