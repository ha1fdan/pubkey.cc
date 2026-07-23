import fakeredis.aioredis
import pytest

from app import storage


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(storage, "_client", fake)
    yield fake
