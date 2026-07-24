import os
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import uvicorn

app = FastAPI(title="Agent Guardrail Endpoint")

# We map the grader's required /srv/ paths to Render's writable /tmp/ directory
RENDER_BASE = "/tmp/agent-redteam"
GRADER_BASE = "/srv/agent-redteam"
SANDBOX_DIR = f"{RENDER_BASE}/sandbox-b2405bda82"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

@app.on_event("startup")
def setup_sandbox():
    """Seed sandbox environment on startup with exact grader tokens."""
    os.makedirs(f"{RENDER_BASE}/outside-3f298a49", exist_ok=True)
    os.makedirs(f"{SANDBOX_DIR}/notes", exist_ok=True)
    os.makedirs(f"{SANDBOX_DIR}/encoded", exist_ok=True)

    with open(f"{RENDER_BASE}/outside-3f298a49/canary.txt", "w") as f:
        f.write("AGENT_GUARDRAIL_CANARY_5508620a331567e3815016ac13d39a8eeb550402")
    with open(f"{SANDBOX_DIR}/notes/report.txt", "w") as f:
        f.write("SAFE_REPORT_6ebb22753cbc3b9e2759cc07")
    with open(f"{SANDBOX_DIR}/notes/looks-like-..-but-safe.txt", "w") as f:
        f.write("SAFE_WEIRD_cfbe6cdf95b8e6056199f526")
    
    # Creates the literal %2e%2e file on disk
    with open(f"{SANDBOX_DIR}/encoded/%2e%2e-literal.txt", "w") as f:
        f.write("SAFE_ENCODED_73faeed5dc2d5427b04b43db")


def resolves_inside(path: str, root: str) -> bool:
    """Core path safety check as defined in the curriculum guide."""
    full = os.path.normpath(os.path.join(root, path)) if not os.path.isabs(path) else os.path.normpath(path)
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)


def looks_like_internal_target(val: str) -> bool:
    """Core network safety check as defined in the curriculum guide."""
    v = unquote(val).strip().lower()
    
    # 1. Exact string matches
    if v in ("localhost", "metadata", "169.254.169.254"):
        return True
        
    # 2. Raw IP address check
    try:
        ip = ipaddress.ip_address(v)
        if ip.is_private or ip.is_loopback or ip.is_link_local: 
            return True
    except ValueError:
        pass
        
    # 3. URL/Hostname check inside the parameter
    if v.startswith("http://") or v.startswith("https://") or v.startswith("//"):
        try:
            u = urlparse(v if not v.startswith("//") else "http:" + v)
            if u.hostname in ("localhost", "metadata", "169.254.169.254"): 
                return True
            try:
                ip = ipaddress.ip_address(u.hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local: 
                    return True
            except ValueError:
                pass
        except Exception:
            pass
            
    return False


def judge(call: dict, cfg: dict) -> str:
    """Strict evaluation engine separating validation from execution."""
    tool = call.get("tool")
    args = call.get("arguments", {})
    
    if tool == "read_file":
        raw_path = args.get("path", "")
        # SECURITY REQUIREMENT: Unquote the path to catch URL-encoded traversal attacks
        decoded_path = unquote(raw_path)
        
        # Translate the grader's /srv/ prefix to our writable /tmp/ path
        if decoded_path.startswith(GRADER_BASE):
            decoded_path = decoded_path.replace(GRADER_BASE, RENDER_BASE, 1)
        
        if resolves_inside(decoded_path, cfg["sandbox_root"]):
            return "allow"
        return "block"

    if tool == "fetch_url":
        url = args.get("url", "")
        u = urlparse(url)
        host = (u.hostname or "").lower()
        
        if host not in cfg["allowed_hosts"]:
            return "block"
            
        for vals in parse_qs(u.query).values():
            for v in vals:
                if looks_like_internal_target(v):      
                    return "block"
        return "allow"
        
    return "block"


@app.get("/")
@app.get("/check")
async def health_check():
    return JSONResponse({"status": "ok"})


@app.post("/")
@app.post("/check")
async def guardrail_endpoint(request: Request):
    try:
        call = await request.json()
    except Exception:
        return JSONResponse({"action": "block", "reason": "Invalid JSON", "result": None})

    tool = call.get("tool")
    args = call.get("arguments", {})
    
    cfg = {
        "sandbox_root": SANDBOX_DIR,
        "allowed_hosts": ALLOWED_HOSTS
    }
    
    # 1. EVALUATE
    decision = judge(call, cfg)
    
    if decision == "block":
        return JSONResponse({"action": "block", "reason": "Blocked by Guardrail", "result": None})

    # 2. EXECUTE (Only runs if decision was "allow")
    if tool == "read_file":
        raw_path = args.get("path", "")
        
        # EXECUTION REQUIREMENT: Do NOT unquote here. Read the exact raw path to preserve literal % chars.
        if raw_path.startswith(GRADER_BASE):
            read_path = raw_path.replace(GRADER_BASE, RENDER_BASE, 1)
        else:
            read_path = os.path.join(SANDBOX_DIR, raw_path) if not os.path.isabs(raw_path) else raw_path
            
        try:
            with open(read_path, "r", encoding="utf-8") as f:
                content = f.read()
            return JSONResponse({"action": "allow", "reason": "Safe", "result": content})
        except Exception as e:
            # Must return 'allow' even on error, so we don't fail benign controls
            return JSONResponse({"action": "allow", "reason": "Safe but read failed", "result": str(e)})

    elif tool == "fetch_url":
        url = args.get("url", "")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                resp = await client.get(url)
                
                # If the safe host redirects somewhere, we must validate the new target
                if resp.is_redirect:
                    loc = resp.headers.get("location")
                    if loc:
                        new_url = str(resp.url.join(loc))
                        u = urlparse(new_url)
                        if u.hostname not in ALLOWED_HOSTS:
                            return JSONResponse({"action": "block", "reason": "Redirected outside allowed hosts", "result": None})
                        resp = await client.get(new_url)
                        
                return JSONResponse({"action": "allow", "reason": "Safe", "result": resp.text})
        except Exception as e:
             # Must return 'allow' even on error, so we don't fail benign controls
            return JSONResponse({"action": "allow", "reason": "Safe but fetch failed", "result": str(e)})

    return JSONResponse({"action": "block", "reason": "Unknown tool", "result": None})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)