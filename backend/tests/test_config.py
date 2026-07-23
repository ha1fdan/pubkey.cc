from app.config import parse_origins


def test_parse_origins_single():
    assert parse_origins("*") == ["*"]


def test_parse_origins_comma_separated():
    assert parse_origins("https://pubkey.cc,https://www.pubkey.cc") == [
        "https://pubkey.cc",
        "https://www.pubkey.cc",
    ]


def test_parse_origins_strips_whitespace_and_drops_empties():
    assert parse_origins(" https://pubkey.cc , , https://api.pubkey.cc ") == [
        "https://pubkey.cc",
        "https://api.pubkey.cc",
    ]
