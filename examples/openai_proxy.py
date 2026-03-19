"""
OpenAI proxy example.

Start the proxy:
    python examples/openai_proxy.py

Then configure your app to use http://localhost:8080 as the OpenAI base URL:
    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:8080/v1", api_key="your-key")
"""
import uvicorn
from prompt_firewall.config import FirewallConfig
from prompt_firewall.middleware.openai_proxy import create_proxy_app

config = FirewallConfig()
config.canary_tokens = ["CANARY-MY-SECRET-TOKEN"]  # detect system prompt leakage

app = create_proxy_app(
    config=config,
    upstream_url="https://api.openai.com",
    scan_input=True,
    scan_output=True,
)

if __name__ == "__main__":
    print("🛡️ prompt-firewall proxy running on http://localhost:8080")
    print("   Upstream: https://api.openai.com")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")
