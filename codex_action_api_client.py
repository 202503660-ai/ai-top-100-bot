"""Contest action API client, generated from the organizer's OpenAPI document.

This module validates the wire shape, not business policy or identity. The caller
must authorize the target and confirm all policy/customer-consent requirements
before executing any operation. The reset operation is deliberately not exposed.
"""
from __future__ import annotations

import asyncio
import copy
import json
import math
import re
import time
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx


DEFAULT_BASE_URL = "https://gyodong-mall-action.aitop100.org"
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
TOOL_RE = re.compile(r"^API_\d{2}$")


class ActionInputError(ValueError):
    """The model supplied arguments outside the published API schema."""


def _validate(value: Any, schema: dict[str, Any], where: str) -> None:
    """Validate the schema subset used by the published request parameters."""
    kind = schema.get("type")
    types = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
    }
    if kind and (kind not in types or not types[kind](value)):
        raise ActionInputError(f"{where}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ActionInputError(f"{where}: invalid value")
    if kind == "string":
        if not value.strip():
            raise ActionInputError(f"{where}: empty string")
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ActionInputError(f"{where}: too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ActionInputError(f"{where}: too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ActionInputError(f"{where}: invalid format")
        if schema.get("format") == "date":
            # OpenAPI date is RFC 3339 full-date. fromisoformat also accepts
            # compact/week formats, so first require the exact wire shape.
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
                raise ActionInputError(f"{where}: expected YYYY-MM-DD")
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ActionInputError(f"{where}: invalid date") from exc
    if kind in ("number", "integer"):
        if isinstance(value, float) and not math.isfinite(value):
            raise ActionInputError(f"{where}: expected finite number")
        if schema.get("format") == "int32" and not -(2**31) <= value < 2**31:
            raise ActionInputError(f"{where}: outside int32 range")
        if "minimum" in schema and value < schema["minimum"]:
            raise ActionInputError(f"{where}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ActionInputError(f"{where}: above maximum")
    if kind == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ActionInputError(f"{where}: too few items")
        for i, item in enumerate(value):
            _validate(item, schema.get("items", {}), f"{where}[{i}]")
    if kind == "object":
        props = schema.get("properties", {})
        missing = set(schema.get("required", [])) - value.keys()
        if missing:
            raise ActionInputError(f"{where}: missing {', '.join(sorted(missing))}")
        if schema.get("additionalProperties") is False:
            extra = value.keys() - props.keys()
            if extra:
                raise ActionInputError(f"{where}: unexpected {', '.join(sorted(extra))}")
        for key, item in value.items():
            if key in props:
                _validate(item, props[key], f"{where}.{key}")


class ActionAPIClient:
    def __init__(
        self,
        token: str,
        *,
        spec_path: str | Path | None = None,
        base_url: str = DEFAULT_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not token or not token.strip():
            raise ValueError("action API token is required")
        self._token = token.strip()
        self.base_url = base_url.rstrip("/")
        self._http_client = http_client
        if spec_path:
            path = Path(spec_path)
        else:
            local_spec = Path(__file__).with_name("액션_API_원문.json")
            parent_spec = Path(__file__).resolve().parent.parent / "액션_API_원문.json"
            path = local_spec if local_spec.exists() else parent_spec
        spec = json.loads(path.read_text(encoding="utf-8"))
        self._operations: dict[str, dict[str, Any]] = {}
        for template, methods in spec["paths"].items():
            for method, op in methods.items():
                op_id = op.get("operationId", "") if isinstance(op, dict) else ""
                name = op_id.replace("-", "_")
                if not TOOL_RE.fullmatch(name) or method.lower() not in ("get", "post"):
                    continue
                properties: dict[str, Any] = {}
                required: list[str] = []
                parameters = []
                for param in op.get("parameters", []):
                    if param.get("in") not in ("path", "query"):
                        continue
                    key = param["name"]
                    properties[key] = copy.deepcopy(param.get("schema", {}))
                    if param.get("description"):
                        properties[key]["description"] = param["description"]
                    if param.get("required"):
                        required.append(key)
                    parameters.append((key, param["in"]))
                req = op.get("requestBody", {})
                body_schema = req.get("content", {}).get("application/json", {}).get("schema")
                if body_schema is not None:
                    properties["body"] = copy.deepcopy(body_schema)
                    if req.get("required"):
                        required.append("body")
                schema = {"type": "object", "properties": properties,
                          "required": required, "additionalProperties": False}
                self._operations[name] = {
                    "method": method.upper(), "path": template.split("?", 1)[0],
                    "parameters": parameters, "schema": schema,
                    "has_body": body_schema is not None,
                    "description": op.get("summary") or op.get("description") or op_id,
                }

    def tools(self) -> list[dict[str, Any]]:
        return [{"type": "function", "function": {
            "name": name, "description": op["description"],
            "parameters": copy.deepcopy(op["schema"]),
        }} for name, op in sorted(self._operations.items())]

    async def execute(
        self, name: str, arguments: dict[str, Any], *, tc_id: str,
        timeout: float = 8.0, max_retries: int = 1,
    ) -> dict[str, Any]:
        """Execute one validated operation and return a JSON-serializable result.

        timeout is a total wall-clock budget including an optional 429/503 wait.
        The caller must bound this further by the remaining end-to-end turn deadline.
        Never automatically retry an ambiguous network failure of a write.
        """
        name = name.replace("-", "_") if isinstance(name, str) else ""
        if name not in self._operations:
            raise ActionInputError("unknown or disallowed action")
        if not isinstance(tc_id, str) or not CASE_RE.fullmatch(tc_id):
            raise ActionInputError("valid trusted TC ID is required")
        op = self._operations[name]
        _validate(arguments, op["schema"], "arguments")
        if timeout <= 0:
            raise ActionInputError("timeout must be positive")
        path = op["path"]
        query = {}
        for key, location in op["parameters"]:
            if key not in arguments:
                continue
            if location == "path":
                path = path.replace("{" + key + "}", quote(str(arguments[key]), safe=""))
            else:
                query[key] = arguments[key]
        headers = {"Authorization": f"Bearer {self._token}",
                   "X-Aitop100-Test-Case-Id": tc_id}
        kwargs: dict[str, Any] = {"params": query, "headers": headers}
        if op["has_body"] and ("body" in arguments or op["method"] == "POST"):
            kwargs["json"] = arguments.get("body", {})
        deadline = time.monotonic() + timeout
        own_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient()
        try:
            for attempt in range(max(0, max_retries) + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"ok": False, "error": "deadline_exceeded"}
                try:
                    response = await asyncio.wait_for(
                        client.request(op["method"], self.base_url + path,
                                       timeout=remaining, **kwargs), timeout=remaining)
                except (httpx.RequestError, asyncio.TimeoutError):
                    return {"ok": False, "error": "transport_error",
                            "outcome_unknown": op["method"] == "POST"}
                if response.status_code == 429:
                    # The cumulative cap does not recover; only retry a valid,
                    # short Retry-After inside this request's total budget.
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = {}
                    if isinstance(payload, dict) and "누적" in str(payload.get("message", "")):
                        return {"ok": False, "status": 429, "error": "quota_exhausted"}
                    if attempt >= max_retries:
                        return {"ok": False, "status": 429, "error": "rate_limited", "details": payload}
                    try:
                        delay = float(response.headers.get("Retry-After", ""))
                    except ValueError:
                        delay = -1
                    if 0 <= delay < deadline - time.monotonic():
                        await asyncio.sleep(delay)
                        continue
                    return {"ok": False, "status": 429, "error": "rate_limited", "details": payload}
                if response.status_code == 503:
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = {}
                    if attempt < max_retries:
                        try:
                            delay = float(response.headers.get("Retry-After", "0.05"))
                        except ValueError:
                            delay = 0.05
                        if 0 <= delay < deadline - time.monotonic():
                            await asyncio.sleep(delay)
                            continue
                    return {"ok": False, "status": 503, "error": "service_unavailable", "details": payload}
                try:
                    payload = response.json()
                except ValueError:
                    payload = None
                if response.is_success:
                    return {"ok": True, "status": response.status_code, "data": payload}
                return {"ok": False, "status": response.status_code,
                        "error": "api_error", "details": payload}
            return {"ok": False, "error": "deadline_exceeded"}
        finally:
            if own_client:
                await client.aclose()
