from __future__ import annotations

import json

import requests


class LLMClient:
    def __init__(self, api_key: str, model: str, base_url: str, timeout: int = 45) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def chat_completion(self, system_prompt: str, user_payload: dict) -> str:
        endpoint = f"{self.base_url}/chat/completions"
        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_payload)},
                ],
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        return content

    def chat_json(self, system_prompt: str, user_payload: dict) -> dict:
        return json.loads(self.chat_completion(system_prompt, user_payload))
