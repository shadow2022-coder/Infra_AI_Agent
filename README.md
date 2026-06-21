# InfraRed AI

InfraRed AI is a Streamlit MVP/demo for reviewing AI-generated application projects before deployment. It combines deterministic security checks, optional parallel AI review, and optional runtime sandbox testing so a reviewer can quickly judge whether an uploaded project is safe to ship, needs caution, or requires manual review.

## Live Demo

Temporary public demo:
[Open InfraRed AI Demo] (https://zany-eureka-v4j54jwrxp9fx7xg-8501.app.github.dev/) . If this stops just run it locally.

To test this get the demo zip from demo (https://github.com/shadow2022-coder/Infra_AI_Agent/blob/main/demo_inputs/meal-prep-ai-demo.zip)

Note:
- This is a temporary Codespaces-hosted demo link.
- If the Codespace stops, the link may stop working until restarted.


## Project Overview

InfraRed AI is designed for local defensive testing. A user uploads a project ZIP, the app extracts and filters relevant files, masks secrets before display or AI use, runs rule-based security checks, and then optionally runs a deeper AI-assisted review and runtime sandbox pass.

This repository is intentionally judge-friendly:

- the app runs locally with Streamlit
- included sample ZIPs can be uploaded directly into the UI
- demo samples contain fake secrets only
- SafeTestAgents and Demo Fallback are both preserved

## What InfraRed AI Does

- Uploads a project ZIP or scans the bundled insecure sample app
- Safely extracts files and ignores junk like `node_modules`, build outputs, and caches
- Detects stack signals such as Next.js, Supabase, Stripe, Docker, Prisma, Vercel, Terraform, and Kubernetes
- Masks secrets before UI display, reports, logs, or AI calls
- Runs deterministic static security checks first
- Optionally runs 5 parallel specialist AI agents plus 1 final reporter
- Optionally runs Docker-based runtime sandbox testing with Playwright screenshots
- Produces both an HTML report and a Markdown fix brief

## Application Workflow

1. Start the Streamlit app locally.
2. Upload a full project ZIP or use the bundled insecure sample.
3. InfraRed AI extracts the ZIP and filters to security-relevant files.
4. The app detects stack signals and masks secrets immediately.
5. Deterministic static security checks run first.
6. The app builds a compressed sanitized context from the most relevant findings and files.
7. If AI review is enabled, 5 specialist agents review the sanitized context in parallel.
8. A final reporter combines the rule findings, AI output, and runtime evidence into a final decision.
9. In `SafeTestAgents` mode, the app also attempts dynamic sandbox testing and Playwright screenshot capture.
10. The UI exposes the final decision, score, evidence, HTML report, and Markdown report.

## Modes

### SafeTestAgents

`SafeTestAgents` is the full review mode. It keeps the static scan, runs the 5 parallel AI specialists plus the final reporter, and attempts disposable Docker sandbox testing with browser/runtime evidence.

Use this mode when you want:

- the real AI Security Board flow
- runtime sandbox testing
- Playwright screenshots
- HTML and Markdown output with sandbox proof when available

### Demo Fallback

`Demo Fallback` is the lightweight demo mode. It preserves the static scan and report flow, but it does not run live sandbox testing or the runtime repair path. It uses fallback AI-style output so the app can still be demonstrated when Docker or an API key is unavailable.

Use this mode when:

- Docker Desktop is not installed or not running
- you want a fast local demo without runtime sandboxing
- you are showing the product flow without spending AI credits

## Static Scan

The static scan is always the first security layer. InfraRed AI:

- filters uploaded files
- detects stack and infrastructure signals
- masks secrets
- runs deterministic rule checks against code, config, infra, and deployment files

This stage works without Docker and without any API key.

## Dynamic Sandbox Testing

Dynamic sandbox testing is part of `SafeTestAgents`. InfraRed AI attempts to start the uploaded project in a disposable local Docker sandbox, probe safe routes like `/`, `/health`, and `/api/health`, and capture sanitized Playwright screenshots and runtime evidence.

Important requirements:

- Docker Desktop or a compatible Docker daemon must be installed and running before dynamic sandbox testing
- Playwright Chromium must be installed locally before screenshot capture will work

If Docker is unavailable, the rest of the product still works and you can use `Demo Fallback`.

## Requirements

- Python 3.10+ recommended
- Docker Desktop or Docker daemon running for dynamic sandbox testing
- Playwright Chromium installed for browser evidence capture

## Local Setup

### macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

### Windows activation

```bash
.venv\Scripts\activate
```

After starting Streamlit, open:

- `http://localhost:8501`

Streamlit also prints a local URL and usually a network URL in the terminal.

## Exact Run Command

```bash
streamlit run app.py
```

## How To Use The App

1. Start Docker Desktop if you want `SafeTestAgents` runtime sandbox testing.
2. Start the app with `streamlit run app.py`.
3. Open the Streamlit URL, usually `http://localhost:8501`.
4. Upload a project ZIP or click `Use sample insecure project`.
5. Review the extraction summary, detected stack, masking status, and deterministic rule findings.
6. In the sidebar under `Settings` and `API`, choose a provider and enter an API key only if you want live AI review.
7. Choose `SafeTestAgents` for the full AI plus sandbox flow, or `Demo Fallback` if Docker is unavailable.
8. Click the run button for the selected mode.
9. Review the Streamlit results, runtime evidence, screenshots, HTML report, and Markdown report.

## Sample Test Projects

Judge-friendly sample ZIPs are provided in [`sample_projects/`](./sample_projects):

- `sample_projects/fitness.zip`
- `sample_projects/meal_prep.zip`

These are intentionally vulnerable demo targets for defensive local testing. They use fake secrets only and are safe to upload into InfraRed AI.

You can also use the bundled sample app button inside the UI, but the ZIPs above are the recommended judge flow because they match a direct upload scenario.

## How To Test With Included Sample ZIP Projects

1. Start the app locally.
2. Upload `sample_projects/fitness.zip` for the FitTrack-style fitness demo flow.
3. Upload `sample_projects/meal_prep.zip` for the second judge-facing demo flow.
4. Run the static scan and review the findings.
5. Use `SafeTestAgents` if Docker Desktop is running and Playwright Chromium is installed.
6. Use `Demo Fallback` if Docker is unavailable.
7. Download and inspect the generated HTML report and Markdown report.

## Judge / Demo Test Flow

1. Clone the repo.
2. Create and activate a virtual environment.
3. Install Python requirements.
4. Install Playwright Chromium.
5. Start Docker Desktop.
6. Run `streamlit run app.py`.
7. Upload `sample_projects/fitness.zip` or `sample_projects/meal_prep.zip`.
8. Run the scan.
9. Review Streamlit results, screenshots, HTML report, and Markdown report.
10. Use Demo Fallback mode if Docker is unavailable.
11. Keep existing functionality intact.

## Provider Notes

- `OpenAI` default base URL: `https://api.openai.com/v1`
- `FastRouter` default base URL: `https://openrouter.ai/api/v1`
- `Custom OpenAI-compatible` lets you provide your own base URL and model

## What Is Sent To AI

- detected stack label
- useful file inventory summary
- masked failed/review findings
- masked snippets from selected useful files
- rule summary counts

## What Is Never Sent To AI

- raw secrets
- user API key
- full repository contents
- binary assets
- junk folders such as `node_modules`, `.git`, build outputs, or caches

## Troubleshooting

### Docker sandbox testing does not start

- Make sure Docker Desktop is installed.
- Make sure Docker Desktop is running before starting `SafeTestAgents`.
- Confirm `docker info` works in your terminal.
- If Docker is unavailable, switch to `Demo Fallback`.

### Playwright screenshots fail

- Run `python -m playwright install chromium`.
- Re-run the app after Playwright Chromium finishes installing.
- Use `Demo Fallback` if you only need the static/demo flow.

### Streamlit command fails

- Activate the virtual environment first.
- Re-run `pip install -r requirements.txt`.
- Start the app with `streamlit run app.py`.

### API review is unavailable

- The API key field is for local/demo testing only.
- Make sure you selected the correct provider and model.
- You can still use static scan and `Demo Fallback` without a live API key.

### Sandbox app is not reachable

- The uploaded project should expose a safe startup path such as a `Dockerfile`, `package.json`, or `requirements.txt`.
- The app should bind to `0.0.0.0`, print its port, and expose `/health` or `/api/health`.

## Safety Notes

- Do not commit real `.env` files or real secrets.
- Fake `.env` files inside the included demo ZIPs are intentional and are part of the defensive test cases.
- InfraRed AI is an MVP/demo and should be treated as a local review tool, not as a production security guarantee.
