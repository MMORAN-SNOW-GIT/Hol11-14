import os
import sys
import json
import argparse
import urllib.parse
from typing import Optional, Tuple

import requests
from dotenv import load_dotenv, find_dotenv
from pathlib import Path


def load_env() -> str:
    dotenv_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path if dotenv_path.exists() else None, override=True)
    return str(dotenv_path if dotenv_path.exists() else "not found")


def resolve_config(agent_endpoint_arg: Optional[str], pat_arg: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    agent_endpoint = agent_endpoint_arg or os.getenv("AGENT_ENDPOINT")
    pat = pat_arg or os.getenv("PAT")
    return agent_endpoint, pat


def print_config(agent_endpoint: Optional[str], pat: Optional[str], dotenv_path: Optional[str]) -> None:
    print("Configuration")
    print("------------")
    print(f".env loaded from: {dotenv_path or 'not found'}")
    print(f"AGENT_ENDPOINT: {agent_endpoint or 'None'}")
    if agent_endpoint:
        try:
            parsed = urllib.parse.urlparse(agent_endpoint)
            print(f" - scheme: {parsed.scheme or 'None'}")
            print(f" - host:   {parsed.netloc or 'None'}")
            print(f" - path:   {parsed.path or 'None'}")
        except Exception as e:
            print(f" - url parse error: {e}")
    print(f"PAT set: {'Yes' if bool(pat) else 'No'}")
    print()


def validate_required(agent_endpoint: Optional[str], pat: Optional[str]) -> bool:
    ok = True
    if not agent_endpoint:
        print("❌ Missing AGENT_ENDPOINT. Set it in .env or pass --agent-endpoint.")
        ok = False
    else:
        parsed = urllib.parse.urlparse(agent_endpoint)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            print("❌ AGENT_ENDPOINT must be a full URL (e.g., https://.../api/v2/cortex/agents/<agent>/chat)")
            ok = False
    if not pat:
        print("❌ Missing PAT. Set it in .env or pass --pat.")
        ok = False
    if not ok:
        print()
    return ok


def test_dns_tls(agent_endpoint: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(agent_endpoint)
        host_url = f"{parsed.scheme}://{parsed.netloc}"
        print(f"🌐 Testing TLS/HTTP reachability to host: {host_url}")
        resp = requests.head(host_url, timeout=15)
        print(f" - Status: {resp.status_code}")
        print(f" - Server: {resp.headers.get('server')}")
        print()
        return True
    except Exception as e:
        print(f"❌ Host reachability error: {e}\n")
        return False


def build_headers(pat: str) -> dict:
    return {
        "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def test_agent_post(agent_endpoint: str, pat: str, question: str) -> bool:
    try:
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": question}],
                }
            ],
            "tool_choice": {"type": "auto"},
            "stream": False,
        }
        print(f"📤 POST (non-stream) to: {agent_endpoint}")
        resp = requests.post(agent_endpoint, headers=build_headers(pat), data=json.dumps(payload), timeout=60)
        print(f" - Status: {resp.status_code}")
        preview = resp.text[:1000]
        print(f" - Body preview ({len(resp.text)} bytes):\n{preview}\n")
        if resp.status_code == 200:
            return True
        else:
            print(classify_status(resp.status_code))
            return False
    except Exception as e:
        print(f"❌ Request error (non-stream): {e}\n")
        return False


def test_agent_stream(agent_endpoint: str, pat: str, question: str, max_lines: int = 30) -> bool:
    try:
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": question}],
                }
            ],
            "tool_choice": {"type": "auto"},
            "stream": True,
        }
        print(f"📡 POST (SSE stream) to: {agent_endpoint}")
        resp = requests.post(
            agent_endpoint,
            headers=build_headers(pat),
            data=json.dumps(payload),
            timeout=120,
            stream=True,
        )
        if resp.status_code != 200:
            print(f" - Status: {resp.status_code}")
            body = resp.text
            print(f" - Body:\n{body[:1000]}\n")
            print(classify_status(resp.status_code))
            return False
        line_count = 0
        for line in resp.iter_lines():
            if not line:
                continue
            line_count += 1
            print(f"[{line_count:03d}] {line.decode('utf-8')}")
            if line_count >= max_lines:
                print("... [truncated for readability] ...\n")
                break
        print()
        return True
    except Exception as e:
        print(f"❌ Request error (stream): {e}\n")
        return False


def classify_status(status: int) -> str:
    if status == 400:
        return "ℹ️ 400 Bad Request: Check payload structure and required fields."
    if status == 401:
        return "ℹ️ 401 Unauthorized: PAT invalid/expired or not authorized for agent."
    if status == 403:
        return "ℹ️ 403 Forbidden: Insufficient privileges to access the agent."
    if status == 404:
        return "ℹ️ 404 Not Found: Verify the agent path/name and account/region in the URL."
    if status == 405:
        return "ℹ️ 405 Method Not Allowed: Endpoint path may be incorrect."
    return f"ℹ️ Unexpected status {status}: Check endpoint and payload."


def test_snowflake_connection() -> bool:
    try:
        import snowflake.connector
        account = os.getenv("ACCOUNT") or (os.getenv("HOST", "").split(".")[0] or None)
        print(f"🧊 Testing Snowflake connection (ACCOUNT={account})")
        conn = snowflake.connector.connect(
            user=os.getenv("DEMO_USER"),
            password=os.getenv("PAT"),
            account=account,
            warehouse=os.getenv("WAREHOUSE"),
            role=os.getenv("DEMO_USER_ROLE"),
        )
        cur = conn.cursor()
        cur.execute("select current_version()")
        version = cur.fetchone()[0]
        cur.close()
        print(f" - Connected. Snowflake version: {version}\n")
        return True
    except Exception as e:
        print(f"❌ Snowflake connect error: {e}\n")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnostics for Cortex Agent connectivity and configuration")
    parser.add_argument("--agent-endpoint", default=None, help="Full https URL to Cortex Agent chat endpoint")
    parser.add_argument("--pat", default=None, help="Programmatic Access Token")
    parser.add_argument("--question", default="ping", help="Test question/message to send")
    parser.add_argument("--no-stream", action="store_true", help="Skip SSE streaming test")
    parser.add_argument("--no-post", action="store_true", help="Skip non-stream POST test")
    parser.add_argument("--snowflake-test", action="store_true", help="Attempt Snowflake connection with PAT")
    args = parser.parse_args()

    dotenv_path = load_env()
    agent_endpoint, pat = resolve_config(args.agent_endpoint, args.pat)
    print_config(agent_endpoint, pat, dotenv_path)

    if not validate_required(agent_endpoint, pat):
        return 2

    ok = True
    ok = test_dns_tls(agent_endpoint) and ok
    if not args.no_post:
        ok = test_agent_post(agent_endpoint, pat, args.question) and ok
    if not args.no_stream:
        ok = test_agent_stream(agent_endpoint, pat, args.question) and ok
    if args.snowflake_test:
        ok = test_snowflake_connection() and ok

    print("Result")
    print("------")
    print("✅ All checks passed" if ok else "❌ One or more checks failed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())


