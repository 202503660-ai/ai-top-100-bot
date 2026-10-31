# AI_TOP_100 Kakao Bot Agent

AI_TOP_100 카카오톡 AI 에이전트 서버 (Render 배포용)

## 주요 엔드포인트
- `POST /webhook` : 카카오 디벨로퍼스 봇 (1초 승인 + 비동기 콜백) 및 카카오 i 오픈빌더 스킬 엔드포인트 (JSON v2.0)
- `GET /admin` : 프롬프트 및 대회 데이터 관리자 (ADMIN_PIN 인증)
- `GET /health` : 서버 헬스체크

## Render 배포
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn kakao_bot_agent_template:app --host 0.0.0.0 --port $PORT`
- Environment Variables:
  - `OPENAI_API_KEY`: OpenAI 또는 Morphfactory API Key (`mak_...` / `sk-...`)
  - `KAKAO_BOT_TOKEN`: 카카오 봇 인증 토큰 (`KakaoAK ...`)
  - `ADMIN_PIN`: 관리자 페이지에 사용할 비공개 PIN (Render에서 설정)
  - `ACTION_API_TOKEN`: 참가자에게 발급된 액션 API 토큰 (`aitop100_...`)
  - `DATABASE_URL`: 영속 PostgreSQL 연결 주소 (`postgresql://...`)
  - `CONTEST_TRUST_FIRST_METADATA`: 대회 메시지 첫머리의 케이스 메타데이터를 신뢰하는 전용 설정 (`1`)
  - `GEMINI_API_KEY`: 사진·음성 인식에 사용할 별도 Gemini API 키 (선택). 미설정이면 `MEDIA_OPENAI_API_KEY`를 선택적으로 사용할 수 있음
  - `GEMINI_MEDIA_MODEL`: 선택 설정이며 기본값은 `gemini-2.5-flash`

Render 웹 서비스의 로컬 파일시스템은 임시 저장소이므로, 서비스 재시작 후에도 대화와 작업 상태를 유지하려면 외부 영속 PostgreSQL(`DATABASE_URL`)을 연결합니다. 로컬 SQLite(`LOCAL_SESSION_DB`)는 개발·테스트용 또는 영구 디스크가 연결된 환경에서만 사용합니다. 연습 데이터의 초기화(`admin_reset_tool.py`)는 최종 제출 전 허용된 시점에만 수동으로 수행합니다.
