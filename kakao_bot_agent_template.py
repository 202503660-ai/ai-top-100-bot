"""
kakao_bot_agent_template.py
AI_TOP_100 대비 카카오톡 AI 에이전트 서버 (v1.5.0 보안 강화판)
- 카카오 디벨로퍼스 봇(Kakao Developers Bot Platform) 완벽 호환
  - 1초 내 HTTP 200 즉각 승인 (Kakao SLA 준수)
  - X-Bot-Callback-Token + KakaoAK 비동기 메시지 콜백 API (https://kapi.kakao.com/v1/bot/callback)
- 카카오 i 오픈빌더 스킬 동기 응답 동시 지원
- 1초 프롬프트 & 지식 데이터 핫스왑 어드민 제어판 (환경변수 PIN 인증 & 비밀값 마스킹)
- Render 클라우드 24시간 무중단 가동 (8분 킵어웨이크 워커)
"""

import os
import sys
import json
import time
import html
import base64
import hmac
import asyncio
import hashlib
import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from contextlib import asynccontextmanager

# Windows 콘솔 인코딩 대응 (UTF-8 이모지 출력 지원)
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from openai import AsyncOpenAI
import httpx
import uvicorn
from pydantic import BaseModel

# -------------------------------------------------------------
# 1. 전역 설정 및 보안 영속화 관리
# -------------------------------------------------------------
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "agent_config.json")

# 환경변수 및 기본 키 보안 관리 (코드베이스/깃 커밋 평문 유출 방지)
_DEFAULT_MOTIF_KEY_B64 = ""
_DEFAULT_KAKAO_TOKEN_B64 = ""

def get_default_motif_key() -> str:
    key = (
        os.getenv("OPENAI_API_KEY")
        or os.getenv("OPEN_AI_KEY")
        or os.getenv("MOTIF_MORPHFACTORY_API_KEY")
        or os.getenv("MOTIF_API_KEY")
    )
    if key:
        return key

    # 로컬 ~/.motif/.env 안전 탐지
    motif_path = os.path.expanduser("~/.motif/.env")
    if os.path.exists(motif_path):
        try:
            with open(motif_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MOTIF_MORPHFACTORY_API_KEY="):
                        val = line.strip().split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass

    try:
        return base64.b64decode(_DEFAULT_MOTIF_KEY_B64).decode("utf-8")
    except Exception:
        return ""

def get_default_kakao_token() -> str:
    return os.getenv("KAKAO_BOT_TOKEN") or base64.b64decode(_DEFAULT_KAKAO_TOKEN_B64).decode("utf-8")

def mask_secret(secret: str) -> str:
    if not secret:
        return "미설정"
    s = str(secret).strip()
    if len(s) > 8:
        return f"{s[:4]}...{s[-4:]}"
    return "설정됨"

default_key = get_default_motif_key()
default_base_url = "https://api-cbt.morphfactory.io/v1" if default_key.startswith("mak_") else ""
default_model = "motif/motif-3" if default_key.startswith("mak_") else "gpt-4o-mini"
default_kakao_token = get_default_kakao_token()

DEFAULT_CONFIG = {
    "kakao_bot_token": default_kakao_token,
    "openai_api_key": default_key,
    "base_url": os.getenv("OPENAI_BASE_URL", default_base_url),
    "model": os.getenv("OPENAI_MODEL", default_model),
    "temperature": 0.3,
    "max_tokens": 180,
    "system_prompt": (
        "당신은 AI_TOP_100 카카오톡 AI 에이전트입니다.\n"
        "1~2문장으로 명확하고 간결하며 친절하게 핵심 정답만 답변하세요."
    ),
    "reference_data": (
        "[AI_TOP_100 미션 가이드]\n"
        "- 대회 일시: 2026년 10월 31일 ~ 11월 1일 자정\n"
        "- 목적: 카카오톡 챗봇 인터페이스를 통한 실시간 고성능 문제 해결\n"
        "- 여기에 대회 당일 주어지는 데이터셋, 지식문서, 프롬프트 지침을 복사해 넣으면 1초 만에 즉시 봇에 반영됩니다."
    )
}

def load_config() -> dict:
    # 1. 로컬 .env 우선 로드 (gitignore 대상이므로 깃 노출 없음)
    for env_candidate in (
        os.path.join(os.path.dirname(__file__), ".env"),
        os.path.join(os.path.dirname(__file__), "..", ".env"),
    ):
        if os.path.exists(env_candidate):
            try:
                with open(env_candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str and not line_str.startswith("#") and "=" in line_str:
                            k, v = line_str.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass

    config = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                config.update({k: v for k, v in saved.items() if v not in ("", None)})
        except Exception as e:
            print(f"[Warning] 설정 파일 로드 실패: {e}")

    env_key = (
        os.getenv("OPENAI_API_KEY")
        or os.getenv("OPEN_AI_KEY")
        or os.getenv("MOTIF_MORPHFACTORY_API_KEY")
        or os.getenv("MOTIF_API_KEY")
    )
    if env_key:
        config["openai_api_key"] = env_key

    if not config.get("openai_api_key"):
        config["openai_api_key"] = get_default_motif_key()

    if config.get("openai_api_key", "").startswith("mak_"):
        if not config.get("base_url"):
            config["base_url"] = "https://api-cbt.morphfactory.io/v1"
        if not config.get("model") or config.get("model") == "gpt-4o-mini":
            config["model"] = "motif/motif-3"

    env_kakao = os.getenv("KAKAO_BOT_TOKEN")
    if env_kakao:
        config["kakao_bot_token"] = env_kakao
    elif not config.get("kakao_bot_token"):
        config["kakao_bot_token"] = get_default_kakao_token()

    if int(config.get("max_tokens", 180)) > 250:
        config["max_tokens"] = 180

    return config

def save_config(cfg: dict):
    try:
        to_save = cfg.copy()
        # 설정 파일 영속화 시 민감 정보는 빈 값으로 저장하여 깃 유출 원천 차단
        to_save["openai_api_key"] = ""
        to_save["kakao_bot_token"] = ""
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, ensure_ascii=False, indent=2)

        # 비밀값이 입력된 경우 gitignore 대상인 .env에 안전하게 로컬 영속화
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        lines = []
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                lines = []

        env_map = {}
        for line in lines:
            line_str = line.strip()
            if line_str and not line_str.startswith("#") and "=" in line_str:
                k, v = line_str.split("=", 1)
                env_map[k.strip()] = v.strip().strip('"').strip("'")

        if cfg.get("openai_api_key"):
            env_map["OPENAI_API_KEY"] = cfg["openai_api_key"]
        if cfg.get("kakao_bot_token"):
            env_map["KAKAO_BOT_TOKEN"] = cfg["kakao_bot_token"]

        if env_map:
            try:
                with open(env_path, "w", encoding="utf-8") as f:
                    for k, v in env_map.items():
                        f.write(f"{k}={v}\n")
            except Exception:
                pass
    except Exception as e:
        print(f"[Warning] 설정 파일 저장 실패 (인메모리 유지): {e}")

current_config = load_config()

# 최근 요청 로그 (메모리에 최대 50건 유지)
request_logs: List[Dict[str, Any]] = []

def add_log(user_id: str, utterance: str, response: str, latency_sec: float, status: str = "success"):
    now_str = datetime.now().strftime("%H:%M:%S")
    request_logs.insert(0, {
        "time": now_str,
        "user_id": user_id,
        "utterance": utterance,
        "response": response,
        "latency": f"{latency_sec:.2f}s",
        "status": status
    })
    if len(request_logs) > 50:
        request_logs.pop()

# -------------------------------------------------------------
# 2. PIN 인증 검증 & 브루트포스 차단 헬퍼
# -------------------------------------------------------------
_failed_pin_attempts: Dict[str, List[float]] = {}

def record_failed_pin(client_ip: str):
    now = time.time()
    attempts = [t for t in _failed_pin_attempts.get(client_ip, []) if now - t < 60.0]
    attempts.append(now)
    _failed_pin_attempts[client_ip] = attempts

def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _failed_pin_attempts.get(client_ip, []) if now - t < 60.0]
    _failed_pin_attempts[client_ip] = attempts
    return len(attempts) >= 12

def is_valid_pin(provided_pin: str) -> bool:
    expected_pin = str(os.getenv("ADMIN_PIN") or "").strip()
    provided = str(provided_pin or "").strip()
    return bool(expected_pin and provided and hmac.compare_digest(provided.encode("utf-8"), expected_pin.encode("utf-8")))

def extract_pin(request: Request, body_pin: str = "", query_pin: str = "") -> str:
    auth_header = request.headers.get("authorization", "")
    bearer_pin = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    return (
        body_pin
        or query_pin
        or request.query_params.get("pin", "")
        or request.headers.get("x-admin-pin", "")
        or request.headers.get("x-pin", "")
        or bearer_pin
    )

# -------------------------------------------------------------
# 3. 무중단 슬립 방지 Lifespan & 클라이언트 웜업
# -------------------------------------------------------------
async def keep_awake_worker():
    """Render 프리티어 슬립 방지용 자동 자체 핑 워커 (8분 주기)"""
    external_url = (
        os.getenv("RENDER_EXTERNAL_URL")
        or "https://ai-top-100-kakao-bot.onrender.com"
    ).rstrip("/")
    health_url = f"{external_url}/health"
    await asyncio.sleep(60)
    while True:
        try:
            await asyncio.sleep(480)
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(health_url)
                print(f"[KeepAwake] 8분 주기 무중단 유지 핑 성공 (상태: {res.status_code})")
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[KeepAwake] 슬립 방지 핑 알림: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 기동 시 클라이언트 및 TLS 연결 사전 웜업 및 24시간 가동 유지"""
    try:
        api_key = (
            current_config.get("openai_api_key")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("MOTIF_MORPHFACTORY_API_KEY")
            or os.getenv("MOTIF_API_KEY")
            or get_default_motif_key()
        )
        base_url = current_config.get("base_url") or ("https://api-cbt.morphfactory.io/v1" if api_key.startswith("mak_") else "")
        if api_key:
            client = get_async_client(api_key, base_url)
            model_name = current_config.get("model", "motif/motif-3")
            extra_body = {"chat_template_kwargs": {"thinking": False}} if "motif" in model_name else None
            await asyncio.wait_for(
                client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": "ping"}],
                    max_tokens=1,
                    extra_body=extra_body
                ),
                timeout=4.0
            )
            print("[Startup] LLM 클라이언트 & TLS 커넥션 풀 웜업 완료!")
    except Exception as e:
        print(f"[Startup] 웜업 알림 (정상 기동 계속): {e}")

    keep_awake_task = asyncio.create_task(keep_awake_worker())
    try:
        yield
    finally:
        keep_awake_task.cancel()
        try:
            await keep_awake_task
        except asyncio.CancelledError:
            pass
        global _cached_client
        if _cached_client:
            try:
                await _cached_client.close()
            except Exception:
                pass

app = FastAPI(
    title="AI_TOP_100 Kakao Bot Agent",
    version="1.5.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# 4. LLM 호출 엔진 (커넥션 풀링 + MoE 추론 고속화 + 3.8초 하드캡)
# -------------------------------------------------------------
_cached_client = None
_cached_loop = None
_cached_key = ""
_cached_base_url = ""

def get_async_client(api_key: str, base_url: str):
    global _cached_client, _cached_loop, _cached_key, _cached_base_url
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if (
        _cached_client is not None
        and _cached_loop is current_loop
        and _cached_key == api_key
        and _cached_base_url == base_url
    ):
        return _cached_client

    kwargs = {"api_key": api_key, "timeout": 4.2}
    if base_url:
        kwargs["base_url"] = base_url
    _cached_client = AsyncOpenAI(**kwargs)
    _cached_loop = current_loop
    _cached_key = api_key
    _cached_base_url = base_url
    return _cached_client

async def call_llm(utterance: str) -> str:
    start_t = time.time()
    api_key = (
        current_config.get("openai_api_key")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("MOTIF_MORPHFACTORY_API_KEY")
        or os.getenv("MOTIF_API_KEY")
        or get_default_motif_key()
    )
    if not api_key:
        return "⚠️ 서버에 API 키가 설정되지 않았습니다. 관리자 페이지(/admin)에서 API 키를 입력해 주세요."

    base_url = current_config.get("base_url") or os.getenv("OPENAI_BASE_URL", "")
    if api_key.startswith("mak_") and not base_url:
        base_url = "https://api-cbt.morphfactory.io/v1"

    model_name = current_config.get("model", "motif/motif-3")
    is_motif = (
        "motif" in model_name.lower()
        or "morphfactory" in base_url.lower()
        or api_key.startswith("mak_")
    )

    try:
        client = get_async_client(api_key, base_url)
    except Exception as e:
        return f"⚠️ 클라이언트 생성 실패: {str(e)[:100]}"

    system_content = current_config.get("system_prompt", "").strip()
    reference_data = current_config.get("reference_data", "").strip()

    if reference_data:
        full_system_prompt = (
            f"{system_content}\n\n"
            f"=== [대회 참조 데이터] ===\n"
            f"{reference_data}\n"
            f"=========================\n"
            "반드시 1~2문장으로 명확하고 간결하게 핵심 정답만 작성하세요."
        )
    else:
        full_system_prompt = (
            f"{system_content}\n\n"
            "반드시 1~2문장으로 명확하고 간결하게 핵심 정답만 작성하세요."
        )

    messages = [
        {"role": "system", "content": full_system_prompt},
        {"role": "user", "content": utterance}
    ]

    extra_body = None
    if is_motif:
        extra_body = {"chat_template_kwargs": {"thinking": False}}

    call_kwargs = {
        "model": model_name,
        "messages": messages,
        "temperature": float(current_config.get("temperature", 0.3)),
        "max_tokens": min(int(current_config.get("max_tokens", 180)), 220),
    }
    if extra_body:
        call_kwargs["extra_body"] = extra_body

    elapsed = time.time() - start_t
    remaining_timeout = 3.8 - elapsed
    if remaining_timeout < 0.8:
        return "질문을 확인했습니다. 핵심 키워드를 포함하여 다시 한번 질문해 주시면 즉시 답변해 드리겠습니다!"

    try:
        response = await asyncio.wait_for(
            client.chat.completions.create(**call_kwargs),
            timeout=remaining_timeout
        )
    except asyncio.TimeoutError:
        print("[Warning] LLM 응답 지연 (3.8초 하드캡 발동)")
        return "질문을 확인했습니다. 핵심 키워드를 포함하여 다시 한번 질문해 주시면 즉시 답변해 드리겠습니다!"
    except Exception as e:
        if "closed" in str(e).lower():
            _cached_client = None
            client = get_async_client(api_key, base_url)
            retry_timeout = 3.8 - (time.time() - start_t)
            if retry_timeout < 0.8:
                return "질문을 확인했습니다. 잠시 후 다시 질문해 주시겠어요?"
            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(**call_kwargs),
                    timeout=retry_timeout
                )
            except Exception as retry_e:
                print(f"[Error] 클라이언트 재시도 실패: {retry_e}")
                return "질문을 확인했습니다. 잠시 후 다시 질문해 주시겠어요?"
        else:
            print(f"[Error] LLM 호출 오류: {e}")
            return f"⚠️ AI 답변 생성 오류: {str(e)[:100]}"

    if not response or not getattr(response, "choices", None) or len(response.choices) == 0:
        return "질문을 확인했습니다. 다시 한번 질문해 주시겠어요?"

    msg = response.choices[0].message
    # Never expose internal model reasoning to customers or admin test replies.
    reply = (msg.content or "").strip()

    if "<think>" in reply and "</think>" in reply:
        reply = reply.split("</think>")[-1].strip()
    elif "<think>" in reply:
        reply = reply.split("<think>", 1)[0].strip()

    if not reply:
        reply = "안녕하세요! 질문해 주시면 성심껏 답변해 드리겠습니다."
    return reply

# -------------------------------------------------------------
# 5. 카카오 디벨로퍼스 비동기 메시지 콜백 API 호출 함수
# -------------------------------------------------------------
async def send_kakao_callback(callback_token: str, reply_text: str, bot_token: str):
    """카카오 디벨로퍼스 REST API 메시지 콜백 (POST https://kapi.kakao.com/v1/bot/callback)"""
    url = "https://kapi.kakao.com/v1/bot/callback"
    headers = {
        "Authorization": f"KakaoAK {bot_token}",
        "X-Bot-Callback-Token": callback_token,
        "Content-Type": "application/json; charset=utf-8"
    }
    body = {
        "skillResponse": {
            "version": "2.0",
            "template": {
                "outputs": [
                    {
                        "simpleText": {
                            "text": reply_text
                        }
                    }
                ]
            }
        }
    }
    if not callback_token or not bot_token:
        return 0
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code == 429:
                try:
                    delay = float(resp.headers.get("retry-after", "0"))
                except (TypeError, ValueError):
                    delay = 0.0
                if 0.0 <= delay <= 2.0:
                    await asyncio.sleep(delay)
                    resp = await client.post(url, json=body, headers=headers)
            if 200 <= resp.status_code < 300:
                logging.info("Kakao callback delivered (HTTP %s)", resp.status_code)
            else:
                logging.warning("Kakao callback rejected (HTTP %s)", resp.status_code)
            return resp.status_code
    except httpx.HTTPError:
        logging.warning("Kakao callback delivery outcome unknown")
        return 0


def fit_simple_text(value: str, limit: int = 485) -> str:
    """Enforce the contest's 500-character maximum on the actual output."""
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        return "문의 내용을 확인하지 못했습니다. 다시 말씀해 주시겠어요?"
    if len(text) <= limit:
        return text
    sentences = re.split(r"(?<=[.!?。])\s+|\n+", text)
    tail = sentences[-1].strip() if len(sentences) > 1 else ""
    if tail and len(tail) < limit // 2:
        return text[: limit - len(tail) - 2].rstrip() + "\n" + tail
    return text[:limit].rstrip()


def simple_text_response(reply: str) -> dict:
    return {"version": "2.0", "template": {"outputs": [{"simpleText": {"text": fit_simple_text(reply)}}]}}


async def dispatch_agent_turn(utterance: str, user_id: str, event_id: Optional[str] = None) -> str:
    if utterance.strip() in ("스킬 테스트", "스킬테스트"):
        return "AI_TOP_100 카카오봇 에이전트 스킬 연결이 정상적으로 완료되었습니다! 질문을 입력하시면 AI가 즉시 답변합니다."
    use_contest_core = bool(
        os.getenv("ACTION_API_TOKEN")
        or os.getenv("DATABASE_URL")
        or os.getenv("LOCAL_SESSION_DB")
        or os.getenv("CONTEST_TRUST_FIRST_METADATA") == "1"
        or utterance.lstrip().lower().startswith("case metadata")
    )
    if not use_contest_core:
        return await call_llm(utterance)
    from agent_core import generate_reply
    cfg = dict(current_config)
    if event_id:
        cfg["_event_id"] = event_id
    return await generate_reply(utterance, user_id, cfg)


_callback_tasks: set = set()
_callback_events: Dict[str, float] = {}


def _callback_event_key(user_id: str, callback_token: str) -> str:
    return hashlib.sha256((user_id + "\0" + callback_token).encode("utf-8")).hexdigest()


async def _run_callback(utterance: str, user_id: str, callback_token: str, bot_token: str) -> None:
    started = time.monotonic()
    try:
        reply = await asyncio.wait_for(dispatch_agent_turn(utterance, user_id), timeout=40.0)
    except Exception:
        logging.exception("Agent turn failed")
        reply = "문의 처리 중 오류가 발생했습니다. 잠시 후 다시 말씀해 주세요."
    reply = fit_simple_text(reply)
    status = await send_kakao_callback(callback_token, reply, bot_token)
    delivered = 200 <= status < 300
    add_log(
        user_id=user_id,
        utterance="",
        response="",
        latency_sec=time.monotonic() - started,
        status="success" if delivered else "callback_failed",
    )

# -------------------------------------------------------------
# 6. 엔드포인트: 루트(/) & 헬스체크(/health)
# -------------------------------------------------------------
@app.get("/")
async def root():
    return RedirectResponse(url="/admin")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AI_TOP_100 Kakao Bot Agent",
        "version": "1.5.0",
        "model": current_config.get("model"),
        "key_configured": bool(current_config.get("openai_api_key")),
        "bot_token_configured": bool(current_config.get("kakao_bot_token")),
        "action_token_configured": bool(os.getenv("ACTION_API_TOKEN")),
        "database_url_configured": bool(os.getenv("DATABASE_URL")),
        "admin_url": "/admin",
        "webhook_url": "/webhook",
        "webhook_alias": "/webhool"
    }

# -------------------------------------------------------------
# 7. 엔드포인트: 카카오 웹훅 (디벨로퍼스 1초 콜백 & 오픈빌더 동기 2중 지원)
# -------------------------------------------------------------
@app.api_route("/webhook", methods=["GET", "POST"])
@app.api_route("/webhook/", methods=["GET", "POST"])
@app.api_route("/webhool", methods=["GET", "POST"])
@app.api_route("/webhool/", methods=["GET", "POST"])
@app.api_route("/api/webhook", methods=["GET", "POST"])
@app.api_route("/api/kakao", methods=["GET", "POST"])
@app.api_route("/skill", methods=["GET", "POST"])
async def kakao_webhook(request: Request):
    if request.method == "GET":
        return {
            "status": "online",
            "service": "AI_TOP_100 Kakao Bot Agent",
            "message": "카카오 봇 웹훅 정상 가동 중 (POST 요청을 수신합니다)",
            "endpoints": ["/webhook", "/webhool"]
        }

    started = time.monotonic()
    raw_body = await request.body()
    if not raw_body or not raw_body.strip():
        return simple_text_response("AI_TOP_100 CS 봇 웹훅이 정상 가동 중입니다.")

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid event"}, status_code=400)

    logging.info("[Kakao Webhook] Received payload: %s", body)

    if not body:
        return simple_text_response("AI_TOP_100 CS 봇 웹훅이 정상 가동 중입니다.")

    d_obj = body.get("d") if isinstance(body.get("d"), dict) else {}
    event_type = body.get("t")
    if isinstance(event_type, str) and event_type in {"ENTRANCE", "CHAT_JOIN", "LEAVE", "AD_REWARD"}:
        return JSONResponse({"status": "ignored"}, status_code=200)

    user_request = body.get("userRequest") if isinstance(body.get("userRequest"), dict) else {}

    # Strict contract test compatibility: reject when utterance is explicitly provided but user is invalid/missing
    if "userRequest" in body and isinstance(user_request, dict):
        if "utterance" in user_request:
            user_val = user_request.get("user")
            if user_val is None or not isinstance(user_val, dict):
                return JSONResponse({"error": "invalid user"}, status_code=400)

    user_info = user_request.get("user") or d_obj.get("author") or d_obj.get("user") or {}
    user_props = user_info.get("properties") if isinstance(user_info, dict) and isinstance(user_info.get("properties"), dict) else {}
    user_id = (
        (user_info.get("id") if isinstance(user_info, dict) else None)
        or user_props.get("botUserKey")
        or user_props.get("bot_user_key")
        or user_props.get("plusfriendUserKey")
        or user_props.get("appUserId")
    )
    if not user_id or not str(user_id).strip():
        user_id = "kakao_test_user"
    user_id = str(user_id).strip()

    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    detail_params = action.get("detailParams") if isinstance(action.get("detailParams"), dict) else {}
    user_params = user_request.get("params") if isinstance(user_request.get("params"), dict) else {}
    media_obj = user_params.get("media") if isinstance(user_params.get("media"), dict) else {}
    media_url = (
        media_obj.get("url")
        or (detail_params.get("media", {}).get("origin") if isinstance(detail_params.get("media"), dict) else "")
        or (params.get("media") if isinstance(params.get("media"), str) else "")
    )
    utterance = (
        d_obj.get("content")
        or d_obj.get("message")
        or d_obj.get("text")
        or d_obj.get("utterance")
        or user_request.get("utterance")
        or params.get("question")
        or params.get("utterance")
        or media_url
    )
    if not isinstance(utterance, str) or not utterance.strip():
        return simple_text_response("안녕하세요! AI_TOP_100 CS 봇입니다. 정상 연결되었습니다. 무엇을 도와드릴까요?")
    utterance = utterance.strip()

    callback_token = d_obj.get("callbackToken") or body.get("callbackToken") or request.headers.get("x-bot-callback-token") or ""
    if callback_token and not isinstance(callback_token, str):
        return JSONResponse({"error": "invalid callback token"}, status_code=400)

    if callback_token:
        bot_token = current_config.get("kakao_bot_token") or get_default_kakao_token()
        if not bot_token:
            return JSONResponse({"error": "bot token unavailable"}, status_code=503)
        now = time.monotonic()
        for old_key, stamp in list(_callback_events.items()):
            if now - stamp > 3600:
                _callback_events.pop(old_key, None)
        key = _callback_event_key(user_id, callback_token)
        if key in _callback_events:
            return JSONResponse({"status": "OK", "message": "Event already queued"}, status_code=200)
        _callback_events[key] = now
        task = asyncio.create_task(_run_callback(utterance, user_id, callback_token, bot_token))
        _callback_tasks.add(task)
        task.add_done_callback(_callback_tasks.discard)
        return JSONResponse({"status": "OK", "message": "Event received, callback queued"}, status_code=200)

    try:
        reply = await asyncio.wait_for(dispatch_agent_turn(utterance, user_id), timeout=40.0)
        status = "success"
    except Exception:
        logging.exception("Agent turn failed")
        reply, status = "문의 처리 중 오류가 발생했습니다. 잠시 후 다시 말씀해 주세요.", "error"
    add_log(user_id=user_id, utterance="", response="", latency_sec=time.monotonic() - started, status=status)
    return simple_text_response(reply)

# -------------------------------------------------------------
# 8. 관리자 API (PIN 인증 필수 및 비밀값 마스킹 보호)
# -------------------------------------------------------------
class ConfigUpdateRequest(BaseModel):
    pin: Optional[str] = ""
    kakao_bot_token: Optional[str] = ""
    openai_api_key: Optional[str] = ""
    model: str = "motif/motif-3"
    temperature: float = 0.3
    max_tokens: int = 180
    system_prompt: str = ""
    reference_data: str = ""

@app.get("/api/config")
async def get_config(request: Request, pin: str = ""):
    client_pin = extract_pin(request, query_pin=pin)
    if not is_valid_pin(client_pin):
        client_ip = request.client.host if request.client else "unknown"
        if is_rate_limited(client_ip):
            raise HTTPException(status_code=429, detail="너무 많은 PIN 인증 실패 요청입니다. 1분 후 다시 시도하세요.")
        record_failed_pin(client_ip)
        await asyncio.sleep(0.3)
        raise HTTPException(status_code=401, detail="PIN 번호가 일치하지 않습니다.")

    cfg = current_config.copy()
    raw_key = cfg.get("openai_api_key", "")
    raw_token = cfg.get("kakao_bot_token", "")

    masked_key = mask_secret(raw_key)
    masked_token = mask_secret(raw_token)

    # API 응답에서 평문 비밀값 및 PIN 노출 차단
    cfg["openai_api_key"] = masked_key
    cfg["kakao_bot_token"] = masked_token
    cfg["masked_key"] = masked_key
    cfg["masked_kakao_token"] = masked_token
    cfg["has_openai_key"] = bool(raw_key)
    cfg["has_kakao_token"] = bool(raw_token)
    cfg["pin"] = "****"
    return cfg

@app.post("/api/config")
async def update_config(payload: ConfigUpdateRequest, request: Request):
    client_pin = extract_pin(request, body_pin=payload.pin)
    if not is_valid_pin(client_pin):
        client_ip = request.client.host if request.client else "unknown"
        if is_rate_limited(client_ip):
            raise HTTPException(status_code=429, detail="너무 많은 PIN 인증 실패 요청입니다. 1분 후 다시 시도하세요.")
        record_failed_pin(client_ip)
        await asyncio.sleep(0.3)
        raise HTTPException(status_code=401, detail="PIN 번호가 일치하지 않습니다.")

    if payload.kakao_bot_token and payload.kakao_bot_token.strip():
        current_config["kakao_bot_token"] = payload.kakao_bot_token.strip()

    if payload.openai_api_key and payload.openai_api_key.strip():
        new_key = payload.openai_api_key.strip()
        current_config["openai_api_key"] = new_key
        if new_key.startswith("mak_"):
            current_config["base_url"] = "https://api-cbt.morphfactory.io/v1"
            if not payload.model or "gpt" in payload.model:
                payload.model = "motif/motif-3"
        elif new_key.startswith("sk-"):
            current_config["base_url"] = ""
            if not payload.model or "motif" in payload.model:
                payload.model = "gpt-4o-mini"

    if "motif" in payload.model.lower():
        if not current_config.get("base_url"):
            current_config["base_url"] = "https://api-cbt.morphfactory.io/v1"
    elif "gpt" in payload.model.lower():
        if current_config.get("base_url") == "https://api-cbt.morphfactory.io/v1":
            current_config["base_url"] = ""

    current_config["model"] = payload.model.strip()
    current_config["temperature"] = payload.temperature
    current_config["max_tokens"] = min(payload.max_tokens, 250)
    current_config["system_prompt"] = payload.system_prompt
    current_config["reference_data"] = payload.reference_data

    global _cached_client
    _cached_client = None

    save_config(current_config)
    return {"status": "success", "message": "설정이 저장되었습니다. 상담 지식은 배포된 knowledge_base.md를 사용합니다."}

class TestChatRequest(BaseModel):
    pin: Optional[str] = ""
    message: str
    session_id: str = "default"


async def _diagnose_database() -> str:
    url = os.getenv("DATABASE_URL", "")
    if not url:
        return "missing"

    def probe() -> bool:
        import psycopg
        with psycopg.connect(url, connect_timeout=5) as connection:
            return connection.execute("SELECT 1").fetchone() == (1,)

    try:
        return "ok" if await asyncio.wait_for(asyncio.to_thread(probe), timeout=7) else "failed"
    except Exception:
        return "failed"


async def _diagnose_action_api() -> str:
    token = os.getenv("ACTION_API_TOKEN", "")
    if not token:
        return "missing"
    try:
        from codex_action_api_client import ActionAPIClient
        result = await ActionAPIClient(token).execute("API_20", {"code": "SUBAK15"}, tc_id="L-60", timeout=6, max_retries=0)
        return "ok" if result.get("ok") else "failed"
    except Exception:
        return "failed"


@app.post("/api/diagnostics")
async def diagnostics(request: Request):
    """Admin-triggered pre-submission checks; no credentials in response."""
    client_ip = request.client.host if request.client else "unknown"
    if is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="잠시 후 다시 시도해 주세요.")
    if not is_valid_pin(extract_pin(request)):
        record_failed_pin(client_ip)
        raise HTTPException(status_code=401, detail="PIN 번호가 일치하지 않습니다.")
    database, action = await asyncio.gather(_diagnose_database(), _diagnose_action_api())
    return {
        "database": database,
        "action_api": action,
        "text_model_configured": bool(current_config.get("openai_api_key")),
        "bot_token_configured": bool(current_config.get("kakao_bot_token")),
        "media_key_configured": bool(os.getenv("GEMINI_API_KEY") or os.getenv("MEDIA_OPENAI_API_KEY")),
        "note": "연결 상태만 확인했습니다. 카카오 수신과 모델 답변은 별도 시험이 필요합니다.",
    }

@app.post("/api/test-chat")
async def test_chat(payload: TestChatRequest, request: Request):
    client_pin = extract_pin(request, body_pin=payload.pin)
    if not is_valid_pin(client_pin):
        client_ip = request.client.host if request.client else "unknown"
        if is_rate_limited(client_ip):
            raise HTTPException(status_code=429, detail="너무 많은 PIN 인증 실패 요청입니다. 1분 후 다시 시도하세요.")
        record_failed_pin(client_ip)
        await asyncio.sleep(0.3)
        raise HTTPException(status_code=401, detail="PIN 번호가 일치하지 않습니다.")

    t0 = time.time()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", payload.session_id):
        raise HTTPException(status_code=400, detail="잘못된 테스트 세션 ID입니다.")
    try:
        reply = await asyncio.wait_for(dispatch_agent_turn(payload.message, "admin-test:" + payload.session_id), timeout=40.0)
    except Exception:
        logging.exception("Admin test turn failed")
        reply = "문의 처리 중 오류가 발생했습니다. 잠시 후 다시 말씀해 주세요."
    reply = fit_simple_text(reply)
    latency = time.time() - t0
    return {
        "reply": reply,
        "latency": f"{latency:.2f}s",
        "char_count": len(reply),
        "exceeds_kakao_limit": len(reply) > 500
    }

@app.get("/api/logs")
async def get_logs(request: Request, pin: str = ""):
    client_pin = extract_pin(request, query_pin=pin)
    if not is_valid_pin(client_pin):
        client_ip = request.client.host if request.client else "unknown"
        if is_rate_limited(client_ip):
            raise HTTPException(status_code=429, detail="너무 많은 PIN 인증 실패 요청입니다. 1분 후 다시 시도하세요.")
        record_failed_pin(client_ip)
        await asyncio.sleep(0.3)
        raise HTTPException(status_code=401, detail="PIN 번호가 일치하지 않습니다.")
    return {"logs": request_logs}

# -------------------------------------------------------------
# 9. 엔드포인트: /admin (보안 PIN 인증 & 마스킹 제어판)
# -------------------------------------------------------------
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, pin: str = ""):
    client_ip = request.client.host if request.client else "unknown"
    client_pin = extract_pin(request, query_pin=pin)
    is_authed = is_valid_pin(client_pin)

    # 1. 미인증 방문자: 시스템 프롬프트 및 민감 데이터를 일절 포함하지 않는 순수 PIN 로그인 화면만 응답
    if not is_authed:
        show_error = bool(pin and not is_authed)
        if show_error:
            record_failed_pin(client_ip)
            await asyncio.sleep(0.3)
        rate_limited = is_rate_limited(client_ip)
        if rate_limited:
            error_alert = (
                '<div class="alert alert-danger py-2 small text-center mb-3">'
                '<i class="bi bi-exclamation-triangle-fill me-1"></i>PIN 시도 횟수를 초과했습니다. 1분 후 다시 시도하세요.'
                '</div>'
            )
        elif show_error:
            error_alert = (
                '<div class="alert alert-danger py-2 small text-center mb-3">'
                '<i class="bi bi-exclamation-triangle-fill me-1"></i>PIN 번호가 올바르지 않습니다.'
                '</div>'
            )
        else:
            error_alert = ""

        login_html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI_TOP_100 에이전트 관리자 인증</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <style>
    :root {{
      --bg-color: #0f172a;
      --card-bg: #1e293b;
      --border-color: #334155;
      --accent: #38bdf8;
      --text: #f8fafc;
    }}
    body {{
      background-color: var(--bg-color);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0;
      padding: 20px;
    }}
    .card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      color: var(--text);
    }}
    .form-control {{
      background-color: #0b1120;
      border: 1px solid var(--border-color);
      color: #f1f5f9;
      border-radius: 8px;
    }}
    .form-control:focus {{
      background-color: #0b1120;
      border-color: var(--accent);
      color: #ffffff;
      box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25);
    }}
    .btn-primary {{
      background-color: #0284c7;
      border-color: #0284c7;
      font-weight: 600;
    }}
    .btn-primary:hover {{
      background-color: #0369a1;
      border-color: #0369a1;
    }}
  </style>
</head>
<body>
  <div class="container" style="max-width: 420px;">
    <div class="card shadow-lg p-4">
      <div class="text-center mb-3">
        <i class="bi bi-shield-lock-fill text-warning fs-1"></i>
        <h4 class="mt-2 text-white">관리자 PIN 인증</h4>
        <p class="text-secondary small">AI_TOP_100 에이전트 제어판입니다.<br>대시보드 접근을 위해 관리자 PIN을 입력하세요.</p>
      </div>
      {error_alert}
      <form method="GET" action="/admin">
        <div class="mb-3">
          <input type="password" name="pin" id="inputPin" class="form-control form-control-lg text-center fw-bold" placeholder="PIN 번호 입력" autocomplete="current-password" autofocus required>
        </div>
        <button type="submit" class="btn btn-primary w-100 py-2 fs-6">
          <i class="bi bi-unlock-fill me-1"></i>대시보드 접속하기
        </button>
      </form>
    </div>
  </div>
  <script>
    if ({'true' if show_error else 'false'}) {{
      localStorage.removeItem("kakao_bot_pin");
    }} else {{
      const savedPin = localStorage.getItem("kakao_bot_pin");
      if (savedPin) {{
        window.location.replace("/admin?pin=" + encodeURIComponent(savedPin));
      }}
    }}
  </script>
</body>
</html>
"""
        return HTMLResponse(content=login_html)

    # 2. 인증 통과 사용자: 비밀값이 마스킹 처리된 안전한 제어판 HTML 응답
    sp = html.escape(current_config.get("system_prompt", ""))
    ref = html.escape(current_config.get("reference_data", ""))
    model = current_config.get("model", "motif/motif-3")
    temp = current_config.get("temperature", 0.3)
    max_tok = current_config.get("max_tokens", 180)

    raw_token = current_config.get("kakao_bot_token", "")
    raw_key = current_config.get("openai_api_key", "")

    masked_token = mask_secret(raw_token)
    masked_key = mask_secret(raw_key)

    key_badge_class = "bg-success" if raw_key else "bg-danger"
    key_badge_text = f"LLM 키 ({masked_key})" if raw_key else "LLM 키 미설정"

    token_badge_class = "bg-success" if raw_token else "bg-warning"
    token_badge_text = f"카카오 토큰 ({masked_token})" if raw_token else "카카오 토큰 미설정"

    motif_selected = "selected" if "motif" in model else ""
    openai_selected = "selected" if "gpt" in model else ""
    client_pin_js = json.dumps(client_pin)

    dashboard_html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI_TOP_100 에이전트 1초 핫스왑 제어판</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <style>
    :root {{
      --bg-color: #0f172a;
      --card-bg: #1e293b;
      --border-color: #334155;
      --accent: #38bdf8;
      --text: #f8fafc;
    }}
    body {{
      background-color: var(--bg-color);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      padding-bottom: 50px;
    }}
    .card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      color: var(--text);
    }}
    .card-header {{
      background-color: rgba(255, 255, 255, 0.03);
      border-bottom: 1px solid var(--border-color);
      font-weight: 600;
    }}
    .form-control, .form-select {{
      background-color: #0b1120;
      border: 1px solid var(--border-color);
      color: #f1f5f9;
      border-radius: 8px;
    }}
    .form-control:focus, .form-select:focus {{
      background-color: #0b1120;
      border-color: var(--accent);
      color: #ffffff;
      box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25);
    }}
    .btn-primary {{
      background-color: #0284c7;
      border-color: #0284c7;
      font-weight: 600;
    }}
    .btn-primary:hover {{
      background-color: #0369a1;
      border-color: #0369a1;
    }}
    .chat-bubble-user {{
      background-color: #0284c7;
      color: white;
      border-radius: 15px 15px 3px 15px;
      padding: 8px 12px;
      margin-bottom: 8px;
      display: inline-block;
      max-width: 80%;
      float: right;
      clear: both;
    }}
    .chat-bubble-bot {{
      background-color: #334155;
      color: white;
      border-radius: 15px 15px 15px 3px;
      padding: 8px 12px;
      margin-bottom: 8px;
      display: inline-block;
      max-width: 80%;
      float: left;
      clear: both;
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>

  <!-- 메인 대시보드 (PIN 인증 통과 시에만 브라우저로 전송) -->
  <div id="mainDashboard" class="container py-4" style="display: block;">
    
    <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary">
      <div>
        <h3 class="mb-1 text-white"><i class="bi bi-robot text-info me-2"></i>AI_TOP_100 에이전트 제어판</h3>
        <p class="text-secondary small mb-0">카카오 디벨로퍼스 봇 연동 &amp; 프롬프트 1초 핫스왑 (Render 24시간 실시간 무중단 가동)</p>
      </div>
      <div>
        <span class="badge {key_badge_class} py-2 px-3 fs-6 me-2">{key_badge_text}</span>
        <span class="badge {token_badge_class} py-2 px-3 fs-6 me-2">{token_badge_text}</span>
        <a href="/admin" class="btn btn-outline-light btn-sm" onclick="localStorage.removeItem('kakao_bot_pin')"><i class="bi bi-box-arrow-right me-1"></i>로그아웃</a>
      </div>
    </div>

    <!-- 카카오 웹훅 안내 및 복사 바 -->
    <div class="alert alert-dark border-secondary mb-4 p-3">
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
        <div>
          <i class="bi bi-link-45deg text-info fs-5 me-2"></i>
          <span><strong>카카오 디벨로퍼스 등록 웹훅 URL:</strong> <code id="webhookUrlDisplay" class="text-warning fs-6">...</code></span>
          <div class="small text-muted mt-1">※ 카카오에 <code>/webhool</code>(오타)로 등록하셔도 100% 정상 작동하도록 이중 수신 처리되어 있습니다.</div>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm btn-info text-white" onclick="copyUrl('/webhook')"><i class="bi bi-clipboard me-1"></i>/webhook 복사</button>
          <button class="btn btn-sm btn-outline-info" onclick="copyUrl('/webhool')"><i class="bi bi-clipboard me-1"></i>/webhool 복사</button>
        </div>
      </div>
    </div>

    <div class="alert alert-dark border-secondary mb-4 p-3">
      <button class="btn btn-sm btn-outline-info" onclick="checkConnections()">DB·액션 API 연결 확인</button>
      <span id="diagnosticResult" class="small ms-2">제출 전에만 사용하세요. 공개 TC 조회 1회가 발생합니다.</span>
    </div>

    <div class="row g-4">
      <!-- 좌측: 설정 영역 -->
      <div class="col-lg-7">
        
        <!-- 시스템 프롬프트 -->
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-cpu-fill text-primary me-2"></i>1. 기존 시스템 프롬프트</span>
            <div class="btn-group btn-group-sm">
              <button class="btn btn-outline-secondary" onclick="setPreset('solver')">대회 해결사</button>
              <button class="btn btn-outline-secondary" onclick="setPreset('cs')">친절 상담봇</button>
              <button class="btn btn-outline-secondary" onclick="setPreset('expert')">팩트 분석가</button>
            </div>
          </div>
          <div class="card-body">
            <textarea id="systemPromptInput" class="form-control" rows="4">{sp}</textarea>
            <div class="form-text text-secondary mt-1">현재 대회 상담 엔진은 이 입력란 대신 배포된 지식 베이스와 기본 응대 지침을 사용합니다.</div>
          </div>
        </div>

        <!-- 실시간 참조 데이터 -->
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-database-fill-gear text-warning me-2"></i>2. 실시간 참조 데이터 / 지식 문서</span>
            <span class="badge bg-secondary">상담 엔진 미반영</span>
          </div>
          <div class="card-body">
            <textarea id="referenceDataInput" class="form-control" rows="6">{ref}</textarea>
            <div class="form-text text-secondary mt-1">대회 상담 지식은 배포된 knowledge_base.md에서 읽습니다. 이 입력란은 현재 상담 응답에 반영되지 않습니다.</div>
          </div>
        </div>

        <!-- AI 모델 & 추론 파라미터 (비밀값 마스킹 적용) -->
        <div class="card mb-4">
          <div class="card-header">
            <i class="bi bi-sliders text-success me-2"></i>3. AI 모델 &amp; 카카오 봇 토큰 설정
          </div>
          <div class="card-body">
            <div class="row g-3">
              <div class="col-md-6">
                <label class="form-label small text-secondary">AI 모델 선택</label>
                <select id="modelSelect" class="form-select">
                  <option value="motif/motif-3" {motif_selected}>motif/motif-3 (Motif 3 CBT - 초고속 MoE)</option>
                  <option value="gpt-4o-mini" {openai_selected}>gpt-4o-mini (OpenAI)</option>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label small text-secondary">Temperature (<span id="tempVal">{temp}</span>)</label>
                <input type="range" class="form-range" id="tempRange" min="0" max="1" step="0.1" value="{temp}" oninput="document.getElementById('tempVal').innerText=this.value">
              </div>
              <div class="col-md-3">
                <label class="form-label small text-secondary">Max Tokens</label>
                <input type="number" id="maxTokensInput" class="form-control" value="{max_tok}" min="50" max="250">
                <div class="form-text text-secondary" style="font-size: 0.72rem;">권장: 150~200</div>
              </div>
              <div class="col-md-6">
                <label class="form-label small text-secondary">카카오 봇 인증 토큰 (현재: <code class="text-info">{masked_token}</code>)</label>
                <input type="password" id="kakaoTokenInput" class="form-control" placeholder="새 토큰 입력 시에만 작성" autocomplete="new-password">
              </div>
              <div class="col-md-6">
                <label class="form-label small text-secondary">LLM API Key (현재: <code class="text-info">{masked_key}</code>)</label>
                <input type="password" id="apiKeyInput" class="form-control" placeholder="새 키 입력 시에만 작성" autocomplete="new-password">
              </div>
            </div>
          </div>
        </div>

        <!-- 저장 버튼 -->
        <div class="d-grid mb-4">
          <button class="btn btn-primary btn-lg shadow" onclick="saveAllConfig()">
            <i class="bi bi-lightning-charge-fill me-2"></i>1초 만에 프롬프트 &amp; 데이터 저장 및 즉시 반영
          </button>
          <div id="saveAlert" class="alert alert-success mt-2 py-2 text-center d-none">
            <i class="bi bi-check-circle-fill me-2"></i>성공적으로 저장되었습니다! 카카오톡 봇에 즉시 반영되었습니다.
          </div>
        </div>

      </div>

      <!-- 우측: 테스트 챗 & 실시간 로그 -->
      <div class="col-lg-5">
        
        <!-- 실시간 대화 테스트 -->
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-chat-dots-fill text-info me-2"></i>실시간 대화 테스트</span>
            <button class="btn btn-sm btn-outline-secondary" onclick="clearTestChat()">지우기</button>
          </div>
          <div class="card-body">
            <label for="testSessionId" class="form-label small">테스트 세션 ID (다른 TC는 다른 ID 사용)</label>
            <input type="text" id="testSessionId" class="form-control mb-2" value="default" maxlength="64" pattern="[A-Za-z0-9._-]+">
            <p class="text-secondary small">첫 메시지에 공개 TC의 case metadata와 고객 문의를 함께 붙여 넣으세요. Ctrl+Enter로 전송합니다.</p>
            <div id="chatHistory" class="p-2 border border-secondary rounded mb-3" style="min-height: 220px; max-height: 280px; overflow-y: auto; background-color: #0b1120;">
              <div class="chat-bubble-bot">안녕하세요! 대회 테스트 케이스로 상담을 확인해 보세요.</div>
            </div>
            <div class="input-group">
              <textarea id="testMessageInput" class="form-control" rows="4" placeholder="case metadata와 테스트 질문을 입력하세요..." onkeydown="if(event.key==='Enter' &amp;&amp; event.ctrlKey) {{ event.preventDefault(); sendTestMessage(); }}"></textarea>
              <button class="btn btn-info text-white" onclick="sendTestMessage()"><i class="bi bi-send-fill"></i></button>
            </div>
            <div id="testMeta" class="text-secondary small mt-2">응답 속도: -</div>
          </div>
        </div>

        <!-- 실시간 카카오톡 요청 로그 -->
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-terminal-fill text-secondary me-2"></i>최근 카톡 요청 로그 (Live)</span>
            <button class="btn btn-sm btn-outline-secondary" onclick="refreshLogs()"><i class="bi bi-arrow-clockwise"></i></button>
          </div>
          <div class="card-body p-2">
            <div id="logContainer" style="max-height: 220px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;" class="p-2 bg-black rounded text-light">
              <div class="text-secondary">수신된 요청 대기 중... 카카오톡에서 말을 걸어보세요.</div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <script>
    const currentPin = {client_pin_js};
    localStorage.setItem("kakao_bot_pin", currentPin);

    async function checkConnections() {{
      const output = document.getElementById("diagnosticResult");
      output.innerText = "연결 확인 중...";
      try {{
        const response = await fetch("/api/diagnostics", {{method: "POST", headers: {{"x-admin-pin": currentPin}}}});
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "확인 실패");
        const status = (v) => v === "ok" ? "정상" : v === "missing" ? "미설정" : "확인 실패";
        output.innerText = `DB: ${{status(data.database)}} · 액션 API: ${{status(data.action_api)}} · 미디어 키: ${{data.media_key_configured ? "설정됨" : "미설정"}}. 실제 카카오 대화는 별도 시험이 필요합니다.`;
      }} catch (error) {{ output.innerText = "연결 확인 실패: " + error.message; }}
    }}

    document.getElementById("webhookUrlDisplay").innerText = window.location.origin + "/webhook";

    function copyUrl(path) {{
      const url = window.location.origin + path;
      navigator.clipboard.writeText(url).then(() => {{
        alert("카카오 디벨로퍼스 웹훅 URL이 복사되었습니다:\\n" + url);
      }}).catch(() => {{
        prompt("웹훅 URL을 복사하세요:", url);
      }});
    }}

    function escapeHtml(str) {{
      if (!str) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }}

    async function saveAllConfig() {{
      const saveAlert = document.getElementById("saveAlert");
      saveAlert.classList.add("d-none");

      const rawMaxTokens = parseInt(document.getElementById("maxTokensInput").value, 10);
      const rawTemp = parseFloat(document.getElementById("tempRange").value);

      const payload = {{
        pin: currentPin,
        kakao_bot_token: document.getElementById("kakaoTokenInput").value.trim(),
        openai_api_key: document.getElementById("apiKeyInput").value.trim(),
        model: document.getElementById("modelSelect").value,
        temperature: isNaN(rawTemp) ? 0.3 : rawTemp,
        max_tokens: isNaN(rawMaxTokens) ? 180 : rawMaxTokens,
        system_prompt: document.getElementById("systemPromptInput").value,
        reference_data: document.getElementById("referenceDataInput").value
      }};

      try {{
        const res = await fetch("/api/config", {{
          method: "POST",
          headers: {{
            "Content-Type": "application/json",
            "x-admin-pin": currentPin
          }},
          body: JSON.stringify(payload)
        }});
        if (!res.ok) {{
          const err = await res.json();
          alert("저장 실패: " + (err.detail || "오류가 발생했습니다."));
          return;
        }}
        saveAlert.classList.remove("d-none");
        setTimeout(() => saveAlert.classList.add("d-none"), 3000);
      }} catch (e) {{
        alert("통신 오류: " + e.message);
      }}
    }}

    async function sendTestMessage() {{
      const input = document.getElementById("testMessageInput");
      const msg = input.value.trim();
      const sessionId = document.getElementById("testSessionId").value.trim();
      if (!msg) return;
      if (!/^[A-Za-z0-9._-]{{1,64}}$/.test(sessionId)) {{
        document.getElementById("testMeta").innerText = "세션 ID는 영문·숫자·점·밑줄·하이픈으로 입력해 주세요.";
        return;
      }}

      input.value = "";
      const history = document.getElementById("chatHistory");
      
      const userBubble = document.createElement("div");
      userBubble.className = "chat-bubble-user";
      userBubble.innerText = msg;
      history.appendChild(userBubble);
      history.scrollTop = history.scrollHeight;

      const botBubble = document.createElement("div");
      botBubble.className = "chat-bubble-bot text-secondary";
      botBubble.innerText = "생각 중...";
      history.appendChild(botBubble);
      history.scrollTop = history.scrollHeight;

      const metaEl = document.getElementById("testMeta");
      metaEl.innerText = "추론 중...";

      try {{
        const res = await fetch("/api/test-chat", {{
          method: "POST",
          headers: {{
            "Content-Type": "application/json",
            "x-admin-pin": currentPin
          }},
          body: JSON.stringify({{ pin: currentPin, message: msg, session_id: sessionId }})
        }});
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "테스트 요청에 실패했습니다.");
        botBubble.className = "chat-bubble-bot";
        botBubble.innerText = data.reply;
        history.scrollTop = history.scrollHeight;
        metaEl.innerText = `응답 속도: ${{data.latency}} | 글자 수: ${{data.char_count}}자`;
      }} catch (e) {{
        botBubble.innerText = "오류 발생: " + e.message;
      }}
    }}

    function clearTestChat() {{
      document.getElementById("chatHistory").innerHTML = '<div class="chat-bubble-bot">대화 내용이 초기화되었습니다.</div>';
    }}

    async function refreshLogs() {{
      try {{
        const res = await fetch(`/api/logs?pin=${{encodeURIComponent(currentPin)}}`, {{
          headers: {{"x-admin-pin": currentPin}}
        }});
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById("logContainer");
        if (!data.logs || data.logs.length === 0) return;
        let h = "";
        data.logs.forEach(l => {{
          h += `<div class="mb-2 pb-1 border-bottom border-dark">
            <span class="text-warning">[${{l.time}}]</span> 
            <span class="text-success">${{l.latency}}</span><br>
            <span class="text-light">Q: ${{escapeHtml(l.utterance)}}</span><br>
            <span class="text-secondary">A: ${{escapeHtml(l.response.substring(0, 80))}}...</span>
          </div>`;
        }});
        container.innerHTML = h;
      }} catch (e) {{}}
    }}

    function setPreset(type) {{
      const sp = document.getElementById("systemPromptInput");
      if (type === "solver") {{
        sp.value = "당신은 AI_TOP_100 경진대회 문제 해결 전문 AI 에이전트입니다. 1~2문장으로 간결하고 정확하게 정답만 답변하세요.";
      }} else if (type === "cs") {{
        sp.value = "당신은 친절한 카카오톡 AI 에이전트입니다. 정중하고 다정하게 1~2문장으로 답변하세요.";
      }} else if (type === "expert") {{
        sp.value = "당신은 냉철하고 정확한 팩트 기반 데이터 분석 전문가입니다. 1~2문장으로 명료하게 핵심 수치와 사실만 전달하세요.";
      }}
    }}

    setInterval(refreshLogs, 3000);
  </script>
</body>
</html>
"""
    return HTMLResponse(content=dashboard_html)

# -------------------------------------------------------------
# 10. 진입점 (로컬 실행 지원)
# -------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"\\n=======================================================")
    print(f"🚀 AI_TOP_100 카카오봇 에이전트 서버 가동 (v1.5.0 보안 강화판)")
    print(f"📌 웹훅 엔드포인트 : http://localhost:{port}/webhook")
    print(f"📌 1초 핫스왑 관리자 페이지 : http://localhost:{port}/admin")
    print(f"=======================================================\\n")
    uvicorn.run("kakao_bot_agent_template:app", host="0.0.0.0", port=port, reload=True)
