# AegisRMF dashboard

Next.js 16 + Tailwind 4. Talks to the AegisRMF REST API with a tenant API key (kept in this browser only).

```bash
# 1. API with the dashboard origin allowed (CORS is an explicit allowlist)
cd ../backend
python tools/demo.py demo_output --keep-db demo.db          # synthetic data; key in demo_output/demo_api_key.txt
AEGIS_DATABASE_URL=sqlite:///./demo.db AEGIS_CORS_ORIGINS=http://localhost:3000 uvicorn aegisrmf.api.main:app

# 2. Dashboard
cd ../frontend && npm install && npm run dev                # http://localhost:3000, paste the key
```

Screens: assessment overview (110-requirement matrix sized by point value + score with trace),
requirement detail (objectives, AI suggestions fenced in dashed violet, citations, implementation statement),
evidence review (accept/reject AI-proposed links grouped by evidence line), POA&M board (170.21 eligibility
on every card), audit trail (hash-chain verification).
