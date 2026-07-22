import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
MESSAGE_TTL_SECONDS = int(os.getenv("MESSAGE_TTL_SECONDS", str(7 * 24 * 3600)))
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "60"))


def parse_origins(value: str) -> list[str]:
    return [origin.strip() for origin in value.split(",") if origin.strip()]


# Comma-separated list of origins allowed to call this relay, e.g.
# "https://pubkey.cc,https://www.pubkey.cc". Defaults to "*" for local dev;
# set explicitly in production so the relay only answers its own frontend.
CORS_ORIGINS = parse_origins(os.getenv("CORS_ORIGINS", "*"))
