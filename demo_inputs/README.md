# Demo inputs

These five folders are small synthetic app snapshots designed for InfraRed AI upload testing.

## Included demos

1. `01_secure_next_vercel`
   Next.js + Stripe + Vercel style app with basic hardening signals.
2. `02_react_firebase_permissive`
   React + Firebase style app with permissive rules and frontend token misuse.
3. `03_fastapi_postgres_internal`
   FastAPI + PostgreSQL style app with weak secrets and unsafe query construction.
4. `04_express_stripe_webhook`
   Express + Stripe style app with missing webhook verification and logging problems.
5. `05_terraform_k8s_public`
   Infra-heavy sample with public cloud exposure and privileged Kubernetes config.
6. `tubescale-bench-insecure`
   Full-stack YouTube-style benchmark with realistic high/critical deployment issues.
7. `tubescale-bench-clean`
   Safer comparison benchmark using the same general architecture with key controls in place.
8. `06_safe_ai_agent_pass`
   Minimal safe Next.js-style app intended to pass the deterministic rule engine and exercise the AI board on a low-risk project.
9. `07_hidden_contextual_risks_pass`
   Passes the deterministic rules but contains subtler business-logic and authorization-design weaknesses for AI-agent evaluation.
10. `demo_of_infra`
   Dedicated InfraRed AI self-test input: passes deterministic rules but still gives the AI board contextual review material.

Each folder is also packaged as a `.zip` for direct upload into the Streamlit app.
