# TDS GA3 — Q2/Q3/Q4 HTTP agent service

This is a **locally tested implementation of the published v3 protocol contracts**, not a verified full-mark hidden-grader solution. Do not claim marks until the exam's Check confirms them. Invoice/mailroom/incident decision accuracy depends heavily on the input and a configured model. No real payments or mail are sent; execution outcomes are recorded only from the grader's authoritative receipt.

## Deploy on Render (fastest route)

1. Upload this directory to **`backend/`** in your existing public GitHub repo `ronitrao222o/tds-ga3-submission`.
2. In Render, **New > Web Service > Build and deploy from a Git repository**. Select that repository and set **Root Directory** to `backend`.
3. Set **Runtime** to Python, **Build Command** to `pip install -r requirements.txt`, and **Start Command** to `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`.
4. Add environment variable `GEMINI_API_KEY` using Render's **Environment** settings (optional for functionality, recommended for case-decision accuracy). Do not paste keys in GitHub or ChatGPT.
5. Deploy. Your service should return JSON at `https://YOUR-SERVICE.onrender.com/`. A Render free service may be slow on its first request, and its filesystem is temporary. For a durable setup use a persistent storage/database service; local SQLite survives requests but not redeploys on free instances.
6. Submit **these three URLs**, replacing YOUR-SERVICE with the actual deployed hostname:

   - **Q2:** `https://YOUR-SERVICE.onrender.com/a2a/`
   - **Q3:** `https://YOUR-SERVICE.onrender.com/v1/mailroom/actions`
   - **Q4:** `https://YOUR-SERVICE.onrender.com/`

7. Verify the Q2 agent card (`https://YOUR-SERVICE.onrender.com/.well-known/agent-card.json`) contains the exact Q2 base URL. Test with `Check` once and inspect grader feedback before spending more checks.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
python tests/test_contract.py
```

Routes:
- `GET /.well-known/agent-card.json` and `/a2a/` A2A 1.0 HTTP+JSON endpoints
- `POST /v1/mailroom/actions` propose/commit; verifies Ed25519 receipts
- `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}`

## Caveats

- The service currently uses SQLite for task state. On free Render instances it can be lost if the instance restarts; durable external SQL storage is required for robust recovery. Full marks need this fixed.
- Prompt-based accuracy requires the model API key and robust field extraction. Fallback heuristics can miss hidden cases, particularly Q2's three precise evidence references and Q3's scoped authorization.
- Q4's OTLP/retry logic has local happy-path tests, but hidden grader cases may require more precise tool arguments, approval branch and trace correlation.
- Some exam versions may use different URL conventions and evaluation shape; follow the live full contract if it differs from the public v3 exam snapshot.
- **Q5** is a time-limited participation game, not a deployable API. After the drawing and guessing windows close, no API implementation can retroactively create genuine participation.
