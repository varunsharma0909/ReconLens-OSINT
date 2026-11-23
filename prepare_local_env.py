"""Prepare a local-only .env without shipping a shared session secret."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parent
env = root / ".env"
if not env.exists():
    env.write_text("SECRET_KEY=\nSESSION_COOKIE_SECURE=false\nALLOW_LIVE_MODE=false\n", encoding="utf-8")
lines = env.read_text(encoding="utf-8").splitlines()
values = {}
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip()
if not values.get("SECRET_KEY") or values["SECRET_KEY"] == "change-me-to-a-long-random-string":
    lines = [line for line in lines if not line.startswith("SECRET_KEY=")]
    lines.append("SECRET_KEY=" + secrets.token_hex(32))
if values.get("SESSION_COOKIE_SECURE", "").lower() != "false":
    lines = [line for line in lines if not line.startswith("SESSION_COOKIE_SECURE=")]
    lines.append("SESSION_COOKIE_SECURE=false")
if values.get("ALLOW_LIVE_MODE", "").lower() != "false":
    lines = [line for line in lines if not line.startswith("ALLOW_LIVE_MODE=")]
    lines.append("ALLOW_LIVE_MODE=false")
env.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("Local .env ready. A unique secret was generated if needed.")
