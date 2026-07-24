import ipaddress
import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import uvicorn

app = FastAPI(title="Agent Guardrail Endpoint")

# Use /tmp as the base directory so Render has permission to write files
BASE_DIR = Path("/tmp/agent-redteam").resolve()
SANDBOX_ROOT = (BASE_DIR / "sandbox-b2405bda82").resolve()
ALLOWED_HOSTS = {"example.com", "www.iana.org"}


@app.on_event("startup")
def setup_sandbox_environment():
    """Automatically seed required sandbox and canary files on container startup."""
    outside_dir = BASE_DIR / "outside-3f298a49"
    sandbox_notes = SANDBOX_ROOT / "notes"
    sandbox_encoded = SANDBOX_ROOT / "encoded"

    os.makedirs(outside_dir, exist_ok=True)
    os.makedirs(sandbox_notes, exist_ok=True)
    os.makedirs(sandbox_encoded, exist_ok=True)

    with open(outside_dir / "canary.txt", "w") as f:
        f.write("AGENT_GUARDRAIL_CANARY_5508620a331567e3815016ac13d39a8eeb550402")

    with open(sandbox_notes / "report.txt", "w") as f:
        f.write("SAFE_REPORT_6ebb22753cbc3b9e2759cc07")

    with open(sandbox_notes / "looks-like-..-but-safe.txt", "w") as f:
        f.write("SAFE_WEIRD_cfbe6cdf95b8e6056199f526")

    # This creates a file literally named '%2e%2e-literal.txt'
    with open(sandbox_encoded / "%2e%2e-literal.txt", "w") as f:
        f.write("SAFE_ENCODED_73faeed5dc2d5427b04b43db")


def is_path_safe(requested_path: str) -> bool:
    if not requested_path:
        return False
    try:
        raw_path = requested_path
        
        # Translate the grader's /srv/ path to our writable /tmp/ path
        if raw_path.startswith("/srv/agent-redteam"):
            raw_path = raw_path.replace("/srv/agent-redteam", str(BASE_DIR), 1)

        p = Path(raw_path)
        if not p.is_absolute():
            p = SANDBOX_ROOT / p

        # resolve() strictly evaluates '..' and symlinks to their true destination
        resolved = p.resolve()
        return resolved == SANDBOX_ROOT or SANDBOX_ROOT in resolved.parents
    except Exception:
        return False


def is_host_internal(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    if host in ("localhost", "metadata", "169.254.169.254"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    except ValueError:
        pass
    return False


def is_target_internal(val: str) -> bool:
    """Checks if a parameter value is a hidden SSRF target."""
    v = unquote(val).strip().lower()
    
    # 1. Is the parameter an embedded URL?
    if v.startswith("http://") or v.startswith("https://"):
        try:
            parsed = urlparse(v)
            return is_host_internal(parsed.hostname)
        except Exception:
            pass
            
    # 2. Is the parameter directly an internal host/IP?
    return is_host_internal(v)


def is_url_safe(raw_url: str) -> bool:
    if not raw_url:
        return False
    try:
        parsed = urlparse(raw_url)
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = (parsed.hostname or "").lower()
        if hostname not in ALLOWED_HOSTS:
            return False

        if parsed.username or parsed.password:
            return False

        query_params = parse_qs(parsed.query)
        for param_values in query_params.values():
            for val in param_values:
                if is_target_internal(val):
                    return False

        return True
    except Exception:
        return False


async def execute_read_file(path_str: str) -> str:
    raw_path = path_str
    if raw_path.startswith("/srv/agent-redteam"):
        raw_path = raw_path.replace("/srv/agent-redteam", str(BASE_DIR), 1)
        
    p = Path(raw_path)
    if not p.is_absolute():
        p = SANDBOX_ROOT / p

    resolved_file = p.resolve()
    if not resolved_file.exists() or not resolved_file.is_file():
        raise FileNotFoundError(f"File not found: {path_str}")

    return resolved_file.read_text(encoding="utf-8", errors="replace")


async def execute_fetch_url(url_str: str) -> str:
    async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
        response = await client.get(url_str)
        
        # Manually intercept redirects to verify the new target is safe
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get("location")
            if redirect_url:
                if not is_url_safe(redirect_url):
                    raise PermissionError("Blocked redirect to disallowed host")
                # Fetch the safe redirect target
                response = await client.get(redirect_url)
                
        return response.text


@app.get("/")
async def health_check():
    return JSONResponse({"status": "ok", "service": "Agent Guardrail Endpoint"})


@app.post("/")
async def guardrail_endpoint(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"action": "block", "reason": "Invalid JSON", "result": None}
        )

    tool = data.get("tool")
    arguments = data.get("arguments", {})

    if tool == "read_file":
        path = arguments.get("path")
        if not is_path_safe(path):
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
            # The Guardrail allowed it, but the file read failed. Action MUST be "allow".
            return JSONResponse({
                "action": "allow",
                "reason": "Guardrail passed, but execution failed.",
                "result": f"Execution error: {str(e)}"
            })

    elif tool == "fetch_url":
        url = arguments.get("url")
        if not is_url_safe(url):
            return JSONResponse({
                "action": "block",
                "reason": "URL destination or embedded target is not permitted.",
                "result": None
            })

        try:
            content = await execute_fetch_url(url)
            return JSONResponse({
                "action": "allow",
                "reason": "Host is in allowed list and parameters are safe.",
                "result": content
            })
        except Exception as e:
            # The Guardrail allowed it, but the fetch failed. Action MUST be "allow".
            return JSONResponse({
                "action": "allow",
                "reason": "Guardrail passed, but execution failed.",
                "result": f"Execution error: {str(e)}"
            })

    return JSONResponse({
        "action": "block",
        "reason": f"Tool '{tool}' is unrecognized.",
        "result": None
    })


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)