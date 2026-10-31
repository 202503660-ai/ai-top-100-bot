"""Administrative tool for pre-submission practice data reset (`resetMyActionData`).

This module is strictly separated from `ActionAPIClient.tools()` so the LLM can
NEVER invoke `POST /api/action-data/reset` during customer conversations.
After a practice reset, bump `CONTEST_GENERATION` so local session/action records
do not collide with the reset remote state.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import time
from typing import Any

import httpx

from codex_action_api_client import CASE_RE, DEFAULT_BASE_URL


async def reset_practice_action_data(
    token: str,
    *,
    tc_id: str = "L-03",
    confirm: bool = False,
    base_url: str = DEFAULT_BASE_URL,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Execute `POST /api/action-data/reset` with explicit human confirmation."""
    if not confirm:
        raise PermissionError("Explicit confirmation (`confirm=True`) is required to reset practice action data.")
    if not token or not token.strip():
        raise ValueError("ACTION_API_TOKEN is required.")
    if not isinstance(tc_id, str) or not CASE_RE.fullmatch(tc_id):
        raise ValueError("A valid public TC ID is required for the X-Aitop100-Test-Case-Id header.")

    url = f"{base_url.rstrip('/')}/api/action-data/reset"
    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "X-Aitop100-Test-Case-Id": tc_id,
    }
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=timeout)
    try:
        response = await client.post(url, headers=headers, timeout=timeout)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        new_generation = f"practice-{int(time.time())}"
        if response.is_success:
            return {
                "ok": True,
                "status": response.status_code,
                "data": payload,
                "next_generation": new_generation,
            }
        return {
            "ok": False,
            "status": response.status_code,
            "error": "reset_failed",
            "details": payload,
        }
    finally:
        if own_client:
            await client.aclose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset AI_TOP_100 practice action data (manual admin tool only).")
    parser.add_argument("--tc-id", default="L-03", help="Public TC ID for X-Aitop100-Test-Case-Id header.")
    parser.add_argument("--confirm", action="store_true", help="Confirm resetting practice action data.")
    args = parser.parse_args()
    token = os.getenv("ACTION_API_TOKEN", "")
    result = asyncio.run(reset_practice_action_data(token, tc_id=args.tc_id, confirm=args.confirm))
    print(result)


if __name__ == "__main__":
    main()
