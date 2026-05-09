"""
Thin Ollama API client. Sends a prompt, returns the response text.

Configure via env vars:
  OLLAMA_URL  (default http://localhost:11434/api/generate)
  OLLAMA_MODEL (default qwen2.5-coder:32b)
"""
import os
import json
import urllib.request
import urllib.error


OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434/api/generate')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'qwen3:32b')


def call(prompt: str, timeout: int = 600) -> str:
    """Send prompt to Ollama, return the response text. Blocks until done."""
    body = {
        'model': OLLAMA_MODEL,
        'prompt': prompt,
        'stream': False,
        'options': {
            'temperature': 0.7,
            'num_predict': 2048,
            # Default ollama context is 4096 tokens — our prompts are larger
            # (parser source + history + research). 16384 fits comfortably.
            'num_ctx': 16384,
        }
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(body).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('response', '')
    except urllib.error.URLError as e:
        raise RuntimeError(f'Ollama request failed: {e}. Is `ollama serve` running and is the model {OLLAMA_MODEL} pulled?')


def check_available() -> bool:
    """Verify Ollama is reachable and the model is pulled."""
    try:
        # The /api/tags endpoint lists pulled models
        tags_url = OLLAMA_URL.replace('/api/generate', '/api/tags')
        with urllib.request.urlopen(tags_url, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            models = [m['name'] for m in data.get('models', [])]
            return any(OLLAMA_MODEL.split(':')[0] in m for m in models)
    except (urllib.error.URLError, json.JSONDecodeError):
        return False


if __name__ == '__main__':
    if not check_available():
        print(f'Ollama not reachable at {OLLAMA_URL} OR model {OLLAMA_MODEL} not pulled.')
        print(f'Run: ollama serve  AND  ollama pull {OLLAMA_MODEL}')
        raise SystemExit(1)
    print(f'Ollama OK at {OLLAMA_URL}, model {OLLAMA_MODEL} available.')
    print('\nTest prompt response:')
    print(call('Say hello in 5 words.'))
