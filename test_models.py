import requests
import json
import time

BASE = "http://localhost:5000"

LOGIN = requests.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin12345"})
cookies = LOGIN.cookies

test_models = [
    ("PollinationsAI", "openai"),
    ("PollinationsAI", "gpt-5-nano"),
    ("PollinationsAI", "sonar-reasoning"),
    ("PollinationsAI", "kimi-k2.5"),
    ("PollinationsAI", "amazon-nova-micro"),
    ("PollinationsAI", "glm-5"),
    ("Perplexity", "auto"),
    ("Perplexity", "gpt41"),
    ("Perplexity", "gpt5"),
    ("Perplexity", "claude2"),
    ("Perplexity", "claude40opus"),
    ("Perplexity", "claude37sonnetthinking"),
    ("Perplexity", "grok"),
    ("Perplexity", "gemini2flash"),
    ("Perplexity", "r1"),
    ("Perplexity", "o3"),
    ("Perplexity", "turbo"),
    ("TeachAnything", "gemma"),
    ("Yqcloud", "gpt-4"),
    ("Auto", "gpt-4"),
]

results = []

for provider, model in test_models:
    print(f"\n{'='*60}")
    print(f"Testing: {provider} / {model}")
    print(f"{'='*60}")
    
    try:
        settings_res = requests.post(
            f"{BASE}/api/settings/admin",
            json={"provider": provider, "model": model},
            cookies=cookies
        )
    except:
        pass

    try:
        res = requests.post(
            f"{BASE}/stream",
            json={"text": "Hay, anda ai model apa?"},
            cookies=cookies,
            stream=True,
            timeout=60
        )
        
        full_text = ""
        for line in res.iter_lines(decode_unicode=True):
            if line and line.startswith("data: "):
                payload = line[6:]
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                    full_text += chunk
                except:
                    pass
        
        answer = full_text.strip()[:300]
        print(f"Response: {answer}")
        results.append({"provider": provider, "model": model, "status": "OK", "response": answer})
        
    except Exception as e:
        err = str(e)[:100]
        print(f"ERROR: {err}")
        results.append({"provider": provider, "model": model, "status": "ERROR", "response": err})
    
    time.sleep(2)

print("\n\n" + "="*80)
print("SUMMARY OF ALL RESULTS")
print("="*80)
for r in results:
    status = "OK" if r["status"] == "OK" else "FAIL"
    resp_preview = r["response"][:150] if r["response"] else "(empty)"
    print(f"\n[{status}] {r['provider']} / {r['model']}")
    print(f"  -> {resp_preview}")
