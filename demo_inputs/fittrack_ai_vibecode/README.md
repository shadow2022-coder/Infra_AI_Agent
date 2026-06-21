# FitTrack AI - Fitness Tracker Demo

Small local demo app for InfraRed AI static scan, AI agents, Docker sandbox runtime testing, screenshots, and report generation.

## Local run

```bash
npm install
npm start
```

The app binds to `0.0.0.0` on port `3000` and prints:

```text
FitTrack AI running on port 3000
```

## Docker run

```bash
docker build -t fittrack-ai-demo .
docker run --rm -p 3000:3000 fittrack-ai-demo
```

## Expected routes

- `/`
- `/dashboard`
- `/login`
- `/admin`
- `/debug`
- `/api/health`
- `/api/workouts`
- `/api/profile`

## Intentional safe demo issues

- Committed `.env` with fake secrets only
- Wildcard CORS
- Missing browser security headers
- Visible fake frontend config in `public/app.js`
- Unprotected `/admin`
- `/debug` shows fake diagnostic data
- Fake token/config values are logged to the console

## Upload into InfraRed AI

1. Run `python scripts/build_fittrack_demo_zip.py`
2. Open InfraRed AI with `streamlit run app.py`
3. Upload `demo_inputs/fittrack_ai_vibecode.zip`
4. Select `SafeTestAgents`
5. Click `Run SafeTestAgents Review`

## Expected SafeTestAgents result

- Static findings for fake `.env`, wildcard CORS, missing headers, exposed frontend config, and unprotected admin/debug
- Sandbox completed in Docker
- Real Playwright screenshots captured
- Report includes `Sandbox Proof / Runtime Evidence`
