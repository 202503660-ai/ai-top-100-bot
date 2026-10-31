# AI_TOP_100 Kakao Bot Agent

AI_TOP_100 카카오톡 AI 에이전트 서버 (Render 배포용)

## 주요 엔드포인트
- `POST /webhook` : 카카오 i 오픈빌더 스킬 엔드포인트 (JSON v2.0)
- `GET /admin` : 프롬프트 및 대회 데이터 1초 핫스왑 웹 관리자 (기본 PIN: 1031)
- `GET /health` : 서버 헬스체크

## Render 배포
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn kakao_bot_agent_template:app --host 0.0.0.0 --port $PORT`
- Environment Variables:
  - `OPENAI_API_KEY`: OpenAI API Key
  - `ADMIN_PIN`: 1031
