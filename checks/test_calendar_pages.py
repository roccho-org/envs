#!/usr/bin/env python3
"""Offline negative gates for the one bounded calendar Pages deploy adapter."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "adapters/calendar_pages.py"
spec = importlib.util.spec_from_file_location("calendar_pages", SOURCE)
assert spec and spec.loader
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SHA = "fed4868e629b5340a7be8e642e628cc72c6e9d14"


def red(fn) -> None:
    try:
        fn()
    except p.Refusal:
        return
    raise AssertionError("invalid request admitted")


def main() -> None:
    event = {
        "repository": {"full_name": p.ENVS_REPO},
        "issue": {"number": 69},
        "comment": {"user": {"id": p.CONTROLLER_ID}, "body": "/deploy-calendar " + SHA},
    }
    assert p.get_comment_sha(event) == SHA
    for bad in ("/deploy-calendar proposals", "/deploy-calendar " + SHA + "\n",
                "/deploy-calendar " + SHA + "; echo secret", "/deploy-calendar ",
                "/deploy-calendar " + ("a" * 41)):
        wrong = json.loads(json.dumps(event))
        wrong["comment"]["body"] = bad
        red(lambda x=wrong: p.get_comment_sha(x))
    wrong = json.loads(json.dumps(event))
    wrong["issue"]["number"] = 70
    red(lambda: p.get_comment_sha(wrong))
    wrong = json.loads(json.dumps(event))
    wrong["comment"]["user"]["id"] = 123
    red(lambda: p.get_comment_sha(wrong))
    wrong = json.loads(json.dumps(event))
    wrong["repository"]["full_name"] = "someone/else"
    red(lambda: p.get_comment_sha(wrong))
    wrong = json.loads(json.dumps(event))
    wrong["issue"]["pull_request"] = {}
    # GitHub pull_request is a populated dict; empty dict is false, so exercise nonempty.
    wrong["issue"]["pull_request"] = {"url": "https://github.com"}
    red(lambda: p.get_comment_sha(wrong))

    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "events.jsonl"
        for good in ('', '\n', '{"date":"2026-10-12","title":"スポーツの日","holiday":true}\n',
                     '{"date":"2026-10-11","title":"遠足"}\n'):
            path.write_text(good, encoding="utf-8")
            p.validate_events(path)
        for bad in ('{"date":"2026-02-30","title":"無効"}\n',
                    '{"date":"2026-11-03","title":"文化の日","holiday":"yes"}\n',
                    '{"date":"2026-11-03","title":"文化の日","secret":"x"}\n',
                    '{"date":"2026-10-11"}\n', '{"date":"2026-10-11","title":2}\n',
                    '{"date":"2026-10-11","title":"ok"}not-json\n'):
            path.write_text(bad, encoding="utf-8")
            red(lambda: p.validate_events(path))
        path.write_bytes(b"x" * 256001)
        red(lambda: p.validate_events(path))
        red(lambda: p.public_readback("private.example.com", Path(temporary)))
        account, token = os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None), os.environ.pop("CLOUDFLARE_API_TOKEN", None)
        try:
            red(lambda: p.deploy(SHA, Path(temporary)))
        finally:
            if account is not None:
                os.environ["CLOUDFLARE_ACCOUNT_ID"] = account
            if token is not None:
                os.environ["CLOUDFLARE_API_TOKEN"] = token
    print("CALENDAR_PAGES_OFFLINE=PASS")


if __name__ == "__main__":
    main()
