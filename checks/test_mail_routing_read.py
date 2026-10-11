#!/usr/bin/env python3
"""Offline security regressions for the M0 Mail GET-only client."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mail_probe", ROOT / "adapters/mail_routing_read.py")
assert SPEC is not None and SPEC.loader is not None
mail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mail)

DOMAIN = "hidden.example.invalid"
ACCOUNT = "a" * 32
ZONE = "b" * 32
TOKEN = "private_cf_fixture_token"
RECIPIENT = "very.private@example.invalid"
ENV = {"CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ACCOUNT_ID": ACCOUNT}


def wrap(value: object) -> bytes:
    payload: dict = {"success": True, "errors": [], "result": value}
    if isinstance(value, list):
        payload["result_info"] = {
            "page": 1, "per_page": 50, "total_pages": 1, "total_count": len(value),
        }
    return json.dumps(payload).encode()


class Response:
    status = 200

    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, *_args: object) -> bytes:
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class Fake:
    """Every mocked call asserts pinned origin, GET and correct bearer."""
    def __init__(self, deny: str = "", bad: str = "", wrong_account: bool = False,
                 duplicate: bool = False, overrides: dict[str, object] | None = None,
                 zone_reply: bytes | None = None, zone_http: int | None = None,
                 zone_transport: bool = False, zone_id: str = ZONE,
                 wrong_name: bool = False, zone_unexpected: bool = False,
                 list_http: tuple[str, int] | None = None, list_transport: str = "",
                 list_unexpected: str = "", list_reply: dict[str, bytes] | None = None,
                 list_pages: dict[str, list[bytes]] | None = None) -> None:
        self.calls: list[str] = []
        self.deny = deny
        self.bad = bad
        self.wrong_account = wrong_account
        self.duplicate = duplicate
        self.overrides = overrides or {}
        self.zone_reply = zone_reply
        self.zone_http = zone_http
        self.zone_transport = zone_transport
        self.zone_id = zone_id
        self.wrong_name = wrong_name
        self.zone_unexpected = zone_unexpected
        self.list_http = list_http
        self.list_transport = list_transport
        self.list_unexpected = list_unexpected
        self.list_reply = list_reply or {}
        self.list_pages = list_pages or {}

    def __call__(self, req: urllib.request.Request, **kwargs: object):
        assert req.get_method() == "GET"
        assert kwargs == {"timeout": 12}
        url = urllib.parse.urlsplit(req.full_url)
        assert url.scheme == "https"
        assert url.netloc == "api.cloudflare.com"
        assert req.get_header("Authorization") == "Bearer " + TOKEN
        path = url.path.removeprefix("/client/v4")
        self.calls.append(path)
        if self.list_http is not None and path == self.list_http[0]:
            raise urllib.error.HTTPError(req.full_url, self.list_http[1], TOKEN, {}, None)
        if path == self.list_transport:
            raise urllib.error.URLError("private transport " + TOKEN)
        if path == self.list_unexpected:
            raise RuntimeError("private internal " + TOKEN)
        if path in self.list_pages:
            # Production's same strict page loop, with bounded synthetic
            # page envelopes. Never a second provider reader.
            page = int(urllib.parse.parse_qs(url.query)["page"][0])
            return Response(self.list_pages[path][page - 1])
        if path in self.list_reply:
            return Response(self.list_reply[path])
        if path == self.deny:
            raise urllib.error.HTTPError(req.full_url, 403, TOKEN, {}, None)
        if path == self.bad:
            return Response(b'{"result":{"contains":"SECRET_RESPONSE"}}')
        if path in self.overrides:
            return Response(wrap(self.overrides[path]))
        if path == "/user/tokens/verify":
            return Response(wrap({"status": "active"}))
        if path == "/zones":
            query = urllib.parse.parse_qs(url.query)
            assert query == {
                "name": [DOMAIN], "account.id": [ACCOUNT], "match": ["all"],
                "page": ["1"], "per_page": ["50"],
            }
            if self.zone_http is not None:
                raise urllib.error.HTTPError(req.full_url, self.zone_http, TOKEN, {}, None)
            if self.zone_transport:
                raise urllib.error.URLError("private transport " + TOKEN)
            if self.zone_unexpected:
                raise RuntimeError("private internal " + TOKEN)
            if self.zone_reply is not None:
                return Response(self.zone_reply)
            wanted = {"name": DOMAIN + ".other" if self.wrong_name else DOMAIN,
                      "id": self.zone_id,
                      "account": {"id": "f" * 32 if self.wrong_account else ACCOUNT}}
            return Response(wrap([wanted, wanted] if self.duplicate else [wanted]))
        if path == f"/zones/{ZONE}/dns_records":
            return Response(wrap([
                {"type": "MX", "name": DOMAIN, "content": "private-mx.invalid"},
                {"type": "TXT", "name": DOMAIN, "content": TOKEN},
            ]))
        if path == f"/zones/{ZONE}/email/routing":
            return Response(wrap({"enabled": True, "status": "ready"}))
        if path == f"/zones/{ZONE}/email/routing/dns":
            return Response(wrap([{"type": "MX", "name": DOMAIN}]))
        if path == f"/zones/{ZONE}/email/routing/rules":
            return Response(wrap([{
                "source": "wrangler", "enabled": True,
                "actions": [{"type": "forward", "value": [RECIPIENT]}],
                "matchers": [{"type": "literal", "field": "to", "value": "m0@" + DOMAIN}],
            }]))
        if path == f"/zones/{ZONE}/email/routing/rules/catch_all":
            return Response(wrap({"enabled": False}))
        if path == f"/accounts/{ACCOUNT}/email/routing/addresses":
            return Response(wrap([{"email": RECIPIENT, "verified": "2026-10-09T00:00:00Z"}]))
        raise AssertionError("unexpected provider path / fallback")


def event(path: Path, value: object = DOMAIN) -> str:
    path.write_text(json.dumps({"inputs": {"domain": value}}), encoding="utf-8")
    return str(path)


def safe(result: dict) -> None:
    text = json.dumps(result)
    for private in (DOMAIN, ACCOUNT, ZONE, TOKEN, RECIPIENT,
                    "private-mx.invalid", "SECRET_RESPONSE"):
        assert private not in text, "private value leaked"
    assert "traceback" not in text.lower()


def test_transport_no_redirect_no_proxy() -> None:
    class Redirect(urllib.request.HTTPSHandler):
        def __init__(self, code: int, location: str) -> None:
            super().__init__()
            self.calls: list[str] = []
            self.code = code
            self.location = location

        def https_open(self, req: urllib.request.Request):
            self.calls.append(req.full_url)
            response = Response(b"")
            response.code = self.code
            response.status = self.code
            response.msg = "synthetic redirect"
            response.info = lambda: {"Location": self.location}
            response.geturl = lambda: req.full_url
            response.close = lambda: None
            return response

    prior = {key: os.environ.get(key) for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
    try:
        os.environ.update({"HTTP_PROXY": "http://proxy.invalid:8888",
                           "HTTPS_PROXY": "http://proxy.invalid:8888",
                           "http_proxy": "http://proxy.invalid:8888",
                           "https_proxy": "http://proxy.invalid:8888"})
        for code in (302, 307):
            for location in ("https://evil.invalid/steal", "https://api.cloudflare.com/client/v4/else"):
                handler = Redirect(code, location)
                opener = mail.safe_opener(handler)
                try:
                    mail._request(opener, TOKEN, "/user/tokens/verify")
                    raise AssertionError("redirect accepted")
                except mail.ReadFailure as failure:
                    assert failure.state == "UNKNOWN"
                assert handler.calls == ["https://api.cloudflare.com/client/v4/user/tokens/verify"]
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "event.json"
        selected = event(path)
        success = Fake()
        answer = mail.observe(selected, ENV, success)
        assert answer["status"] == "READ_OBSERVED", answer
        assert all(s == "OBSERVED" for s in answer["read"].values())
        assert len(success.calls) == len(mail.STEPS)
        assert "zone_unknown_reason" not in answer
        assert "rules_unknown_reason" not in answer and "addresses_unknown_reason" not in answer
        assert answer["write_authority"] == answer["mail_arrival"] == "NOT_PROVEN"
        assert answer["facts"]["token_active"] is True
        assert answer["facts"]["routing_ready"] is True and answer["facts"]["catch_all_enabled"] is False
        assert answer["counts"]["verified_destinations"] == 1
        assert "rules_unknown_gate" not in answer
        safe(answer)

        # Actual production read_rules validator, via existing Fake GET-only
        # _request/_list/observe path; no second parser or provider action.
        rules_endpoint = f"/zones/{ZONE}/email/routing/rules"

        def valid_rule(source: str = "api") -> dict:
            return {"enabled": True, "source": source,
                    "actions": [{"type": "forward", "value": [RECIPIENT]}],
                    "matchers": [{"type": "literal", "field": "to", "value": "m0@" + DOMAIN}]}

        def with_matcher(matcher: object) -> dict:
            return {**valid_rule(), "matchers": [matcher]}

        def rule_ok(rows: list[dict], wrangler: int = 0) -> None:
            mock = Fake(overrides={rules_endpoint: rows})
            got = mail.observe(selected, ENV, mock)
            assert got["status"] == "READ_OBSERVED", got
            assert got["read"]["rules"] == "OBSERVED"
            assert got["counts"]["rules"] == len(rows)
            assert got["counts"]["enabled_rules"] == len(rows)
            assert got["counts"]["wrangler_rules"] == wrangler
            assert "rules_unknown_reason" not in got
            assert "rules_unknown_shape" not in got
            assert "rules_unknown_gate" not in got
            assert got["write_authority"] == got["mail_arrival"] == "NOT_PROVEN"
            assert mock.calls.count(rules_endpoint) == 1
            safe(got)

        def rule_red(row: dict, gate: str) -> None:
            mock = Fake(overrides={rules_endpoint: [row]})
            got = mail.observe(selected, ENV, mock)
            assert got["status"] == "INCOMPLETE", got
            assert got["read"]["rules"] == "UNKNOWN"
            assert got["rules_unknown_reason"] == "rule_item_shape"
            assert got["rules_unknown_gate"] == gate, (gate, got)
            assert gate in mail.RULE_ITEM_GATES
            assert "rules_unknown_shape" not in got
            assert all(key not in got["counts"] for key in
                       ("rules", "enabled_rules", "wrangler_rules"))
            assert got["read"]["zone"] == got["read"]["addresses"] == "OBSERVED"
            assert got["counts"]["account_destinations"] == 1
            assert "addresses_unknown_reason" not in got
            assert "zone_unknown_reason" not in got
            assert mock.calls.count(rules_endpoint) == 1
            assert got["write_authority"] == got["mail_arrival"] == "NOT_PROVEN"
            safe(got)

        # Native type=all needs no matcher field/value. Proven source api
        # vs wrangler remains distinct; no absent source defaults to api.
        rule_ok([with_matcher({"type": "all"})])
        rule_ok([valid_rule(), with_matcher({"type": "all"})])
        rule_ok([valid_rule("wrangler"), with_matcher({"type": "all"})], wrangler=1)
        rule_ok([with_matcher({"type": "all", "field": "to"})])
        rule_ok([with_matcher({"type": "all", "value": "m0@" + DOMAIN})])
        rule_ok([{"enabled": True, "source": "api",
                 "actions": [{"type": "drop"}], "matchers": [{"type": "all"}]}])

        # Invalid combinations prove the FIRST gate in ordered production
        # path: enabled -> source -> actions -> matchers -> type -> field -> value.
        for row, gate in (
            ({**valid_rule(), "enabled": "false", "source": "unknown"}, "enabled_unknown"),
            ({k: v for k, v in valid_rule().items() if k != "enabled"}, "enabled_unknown"),
            ({k: v for k, v in valid_rule().items() if k != "source"}, "source_unknown"),
            ({**valid_rule(), "source": "other", "actions": []}, "source_unknown"),
            ({**valid_rule(), "source": None}, "source_unknown"),
            ({k: v for k, v in valid_rule().items() if k != "actions"}, "actions_unknown"),
            ({**valid_rule(), "actions": []}, "actions_unknown"),
            ({**valid_rule(), "actions": [{"value": [RECIPIENT]}]}, "actions_unknown"),
            ({**valid_rule(), "actions": [{"type": "redirect"}]}, "actions_unknown"),
            ({**valid_rule(), "actions": [{"type": "forward"}]}, "actions_unknown"),
            ({**valid_rule(), "actions": [{"type": "worker", "value": [None]}]}, "actions_unknown"),
            ({k: v for k, v in valid_rule().items() if k != "matchers"}, "matchers_unknown"),
            ({**valid_rule(), "matchers": []}, "matchers_unknown"),
            ({**valid_rule(), "matchers": [None]}, "matchers_unknown"),
            (with_matcher({}), "matcher_type_invalid"),
            (with_matcher({"type": "regex"}), "matcher_type_invalid"),
            (with_matcher({"type": True}), "matcher_type_invalid"),
            (with_matcher({"type": "literal"}), "matcher_field_invalid"),
            (with_matcher({"type": "literal", "field": "from", "value": RECIPIENT}),
             "matcher_field_invalid"),
            (with_matcher({"type": "all", "field": "from"}), "matcher_field_invalid"),
            (with_matcher({"type": "literal", "field": "to"}), "matcher_value_invalid"),
            (with_matcher({"type": "literal", "field": "to", "value": ""}), "matcher_value_invalid"),
            (with_matcher({"type": "literal", "field": "to", "value": "  "}), "matcher_value_invalid"),
            (with_matcher({"type": "literal", "field": "to", "value": False}), "matcher_value_invalid"),
            (with_matcher({"type": "all", "value": ""}), "matcher_value_invalid"),
            (with_matcher({"type": "literal", "field": "to", "value": "a" * 91}),
             "matcher_value_invalid"),
        ):
            rule_red(row, gate)

        # Complete 51-item list: a single invalid LAST item yields no
        # rejected-list counts even when page 1 was valid.
        def paged_rule_packet(rows: list[dict], page: int) -> bytes:
            return json.dumps({
                "success": True, "result": rows,
                "result_info": {"page": page, "count": len(rows), "per_page": 50,
                                "total_count": 51, "total_pages": 2},
            }).encode()

        mock = Fake(list_pages={rules_endpoint: [
            paged_rule_packet([valid_rule()] * 50, 1),
            paged_rule_packet([with_matcher({"type": "literal"})], 2),
        ]})
        got = mail.observe(selected, ENV, mock)
        assert got["read"]["rules"] == "UNKNOWN"
        assert got["rules_unknown_reason"] == "rule_item_shape"
        assert got["rules_unknown_gate"] == "matcher_field_invalid"
        assert all(key not in got["counts"] for key in
                   ("rules", "enabled_rules", "wrangler_rules"))
        assert mock.calls.count(rules_endpoint) == 2
        safe(got)

        # An explicit denial or a pagination/envelope failure cannot carry
        # a rule-item diagnostic gate.
        for fixture in (Fake(list_http=(rules_endpoint, 403)),
                        Fake(list_reply={rules_endpoint: b'{"success":true,"result":[{}]}' })):
            got = mail.observe(selected, ENV, fixture)
            assert got["read"]["rules"] in ("DENIED", "UNKNOWN")
            assert "rules_unknown_gate" not in got
            safe(got)

        # Test the actual main() JSON output with the production validator
        # and an offline opener. No raw matcher/source/recipient is printed.
        original = mail.safe_opener
        saved_env = dict(os.environ)
        try:
            mail.safe_opener = lambda: Fake(overrides={
                rules_endpoint: [with_matcher({"type": "literal"})],
            })
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            output = io.StringIO()
            with redirect_stdout(output):
                assert mail.main() == 2
            closed = json.loads(output.getvalue())
            assert closed["rules_unknown_reason"] == "rule_item_shape"
            assert closed["rules_unknown_gate"] == "matcher_field_invalid"
            assert "rules" not in closed["counts"]
            safe(closed)
        finally:
            mail.safe_opener = original
            os.environ.clear()
            os.environ.update(saved_env)

        # Domain is an explicit non-secret native workflow selector; it
        # remains excluded from adapter stdout, provider identities and logs.
        for wrong in ("", "xyz", "Z" * 64, 3, None, {"name": DOMAIN},
                      "https://" + DOMAIN, "*.example.invalid", DOMAIN + " "):
            fixture = Fake()
            result = mail.observe(event(path, wrong), ENV, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)
        selected = event(path)
        for missing in ({}, {"CLOUDFLARE_API_TOKEN": TOKEN},
                        {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT},
                        {"CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ACCOUNT_ID": "f" * 31}):
            fixture = Fake()
            result = mail.observe(selected, missing, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)

        for fixture in (Fake(wrong_account=True), Fake(duplicate=True)):
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert result["zone_unknown_reason"] in ("owner_or_id_mismatch", "multiple_match")
            assert "addresses" not in result["counts"]
            safe(result)

        # HTTP refusal is per-operation, not proof of missing Write access.
        for endpoint in ("/user/tokens/verify", "/zones",
                         f"/zones/{ZONE}/email/routing/rules",
                         f"/accounts/{ACCOUNT}/email/routing/addresses"):
            fixture = Fake(deny=endpoint)
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert "DENIED" in result["read"].values()
            assert len(fixture.calls) == len(set(fixture.calls))
            safe(result)

        bad_objects = (
            ("/user/tokens/verify", {}, "token"),
            ("/zones", [], "zone"),
            (f"/zones/{ZONE}/dns_records", [{}], "dns"),
            (f"/zones/{ZONE}/dns_records", [{"type": None}], "dns"),
            (f"/zones/{ZONE}/email/routing/dns", [{}], "routing_dns"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [],
            }], "rules"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [], "matchers": "literal",
            }], "rules"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [], "matchers": [{}],
            }], "rules"),
            (f"/zones/{ZONE}/email/routing", {}, "routing"),
            (f"/zones/{ZONE}/email/routing", {"enabled": "false", "status": "ready"}, "routing"),
            (f"/zones/{ZONE}/email/routing", {"enabled": False}, "routing"),
            (f"/zones/{ZONE}/email/routing/rules/catch_all", {}, "catch_all"),
            (f"/zones/{ZONE}/email/routing/rules/catch_all", {"enabled": "false"}, "catch_all"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT}], "addresses"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT, "verified": True}], "addresses"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT, "verified": "false"}], "addresses"),
        )
        for path_name, response, step in bad_objects:
            fixture = Fake(overrides={path_name: response})
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE" and result["read"][step] == "UNKNOWN", (step, result)
            safe(result)
        for status in ("disabled", "expired", "inactive"):
            result = mail.observe(selected, ENV, Fake(overrides={"/user/tokens/verify": {"status": status}}))
            assert result["status"] == "INCOMPLETE"
            assert result["read"]["token"] == "OBSERVED" and result["facts"]["token_active"] is False
            safe(result)

        # Zone diagnostic is a single closed non-secret reason code for
        # UNKNOWN *only*: these are fully synthetic original decision paths,
        # never a second Cloudflare dispatch or a guessed scope diagnosis.
        def zone_case(fixture: Fake, expected: str) -> None:
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert result["read"]["token"] == "OBSERVED"
            assert result["read"]["zone"] == "UNKNOWN"
            assert result["zone_unknown_reason"] == expected, (result, expected)
            assert expected in mail.ZONE_UNKNOWN_REASONS
            assert result["facts"] == {"token_active": True}
            assert result["counts"] == {}
            assert all(result["read"][step] == "UNKNOWN"
                       for step in mail.STEPS if step not in ("token", "zone"))
            assert fixture.calls == ["/user/tokens/verify", "/zones"], fixture.calls
            safe(result)

        zone_case(Fake(overrides={"/zones": []}), "zero_match")
        zero_pages = json.loads(wrap([]))
        zero_pages["result_info"]["total_pages"] = 0
        zone_case(Fake(zone_reply=json.dumps(zero_pages).encode()), "zero_match")
        zone_case(Fake(duplicate=True), "multiple_match")
        zone_case(Fake(wrong_account=True), "owner_or_id_mismatch")
        zone_case(Fake(wrong_name=True), "owner_or_id_mismatch")
        zone_case(Fake(zone_id="not-an-id"), "owner_or_id_mismatch")
        for http_status in (302, 429, 500):
            zone_case(Fake(zone_http=http_status), "http_other")
        zone_case(Fake(zone_transport=True), "transport")
        zone_case(Fake(zone_unexpected=True), "unclassified")
        zone_case(Fake(bad="/zones"), "invalid_payload_or_pagination")
        zone_case(Fake(zone_reply=b'{not-json-private-body'), "invalid_payload_or_pagination")
        for broken in (
            {"result_info": {"page": 1, "per_page": 50, "total_pages": 1, "total_count": 1},
             "success": True, "result": []},
            {"result_info": {"page": 2, "per_page": 50, "total_pages": 1, "total_count": 0},
             "success": True, "result": []},
            {"result_info": {"page": 1, "per_page": 50, "total_pages": 0, "total_count": 1},
             "success": True, "result": [{"name": DOMAIN, "id": ZONE, "account": {"id": ACCOUNT}}]},
            {"result_info": {"page": 1, "per_page": 50, "total_pages": "1", "total_count": 0},
             "success": True, "result": []},
        ):
            zone_case(Fake(zone_reply=json.dumps(broken).encode()), "invalid_payload_or_pagination")

        # An explicit 401/403 is DENIED, not UNKNOWN; a valid empty rules
        # or account-destinations list is OBSERVED with an actual zero count.
        for http_status in (401, 403):
            fixture = Fake(zone_http=http_status)
            denied = mail.observe(selected, ENV, fixture)
            assert denied["read"]["zone"] == "DENIED"
            assert "zone_unknown_reason" not in denied
            safe(denied)
        for path_name, count_key in (
            (f"/zones/{ZONE}/email/routing/rules", "rules"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", "account_destinations"),
        ):
            passed = mail.observe(selected, ENV, Fake(overrides={path_name: []}))
            assert passed["status"] == "READ_OBSERVED"
            assert passed["counts"][count_key] == 0
            assert "zone_unknown_reason" not in passed
            safe(passed)

        # Diagnose only the two remaining read4 UNKNOWN lists. Do not change
        # the strict item/pagination validation or send any real provider GET.
        for step, endpoint, count_key, shape in (
            ("rules", f"/zones/{ZONE}/email/routing/rules", "rules", "rule_item_shape"),
            ("addresses", f"/accounts/{ACCOUNT}/email/routing/addresses",
             "account_destinations", "address_item_shape"),
        ):
            diagnostic_key = f"{step}_unknown_reason"

            def list_case(fixture: Fake, expected: str, gate: str | None = None) -> None:
                got = mail.observe(selected, ENV, fixture)
                assert got["status"] == "INCOMPLETE"
                assert got["read"]["token"] == got["read"]["zone"] == "OBSERVED"
                assert got["read"][step] == "UNKNOWN"
                assert got[diagnostic_key] == expected, (got, expected)
                shape_key = f"{step}_unknown_shape"
                if gate is None:
                    assert shape_key not in got, (got, shape_key)
                else:
                    assert expected == "invalid_payload_or_pagination"
                    assert gate in mail.LIST_UNKNOWN_SHAPES
                    assert got.get(shape_key) == gate, (got, gate)
                assert count_key not in got["counts"]
                assert "zone_unknown_reason" not in got
                other = "addresses" if step == "rules" else "rules"
                assert got["read"][other] == "OBSERVED"
                assert f"{other}_unknown_reason" not in got
                assert f"{other}_unknown_shape" not in got
                assert fixture.calls.count(endpoint) == 1
                assert len(fixture.calls) == len(set(fixture.calls))
                assert got["write_authority"] == got["mail_arrival"] == "NOT_PROVEN"
                safe(got)

            def packet(value: object, info: object = ...) -> bytes:
                response = {"success": True, "result": value}
                if info is not ...:
                    response["result_info"] = info
                return json.dumps(response).encode()

            list_case(Fake(list_transport=endpoint), "transport")
            for status in (302, 429, 500):
                list_case(Fake(list_http=(endpoint, status)), "http_other")
            list_case(Fake(bad=endpoint), "invalid_payload_or_pagination", "invalid_envelope")
            list_case(Fake(list_reply={endpoint: b'{private-invalid-json:'}),
                      "invalid_payload_or_pagination", "invalid_json")
            list_case(Fake(list_reply={endpoint: b' ' * (mail.MAX_RESPONSE + 1)}),
                      "invalid_payload_or_pagination", "response_size")
            list_case(Fake(list_reply={endpoint: packet([])}),
                      "invalid_payload_or_pagination", "pagination_missing")
            list_case(Fake(list_reply={endpoint: packet(None, {})}),
                      "invalid_payload_or_pagination", "invalid_result")
            list_case(Fake(list_reply={endpoint: packet({}, {})}),
                      "invalid_payload_or_pagination", "invalid_result")
            list_case(Fake(list_reply={endpoint: packet(["private"], {})}),
                      "invalid_payload_or_pagination", "nonobject_item")
            list_case(Fake(list_reply={endpoint: packet([], "not-an-object")}),
                      "invalid_payload_or_pagination", "pagination_invalid")
            info = json.loads(wrap([]))["result_info"]
            # The first rejected REQUIRED total is now precise by field and
            # category. These are only closed reason codes, never real values.
            for invalid, gate in (
                ({key: value for key, value in info.items() if key != "total_count"},
                 "total_count_missing"),
                ({**info, "total_pages": True}, "total_pages_type"),
                ({**info, "total_count": False}, "total_count_type"),
                ({**info, "total_pages": "1"}, "total_pages_type"),
                ({**info, "total_count": "0"}, "total_count_type"),
                ({**info, "total_pages": -1}, "total_pages_range"),
                ({**info, "total_count": -1}, "total_count_range"),
                ({**info, "total_pages": mail.MAX_PAGES + 1}, "total_pages_range"),
                ({**info, "total_count": mail.MAX_PAGES * mail.PAGE_SIZE + 1},
                 "total_count_range"),
                # A logically contradictory zero-pages/nonzero-total envelope
                # remains the original pagination_invalid gate.
                ({**info, "total_pages": 0, "total_count": 1}, "pagination_invalid"),
            ):
                list_case(Fake(list_reply={endpoint: packet([], invalid)}),
                          "invalid_payload_or_pagination", gate)
            # When several fields fail, the FIRST field-specific rejection
            # wins: pages type/range, then count missing/type/range,
            # before optional pagination metadata.
            for invalid, first_gate in (
                ({"total_count": "0", "page": 2}, "total_count_type"),
                ({**info, "total_pages": True, "total_count": "0"},
                 "total_pages_type"),
                ({**info, "total_pages": -1, "total_count": None},
                 "total_pages_range"),
                ({key: value for key, value in {**info, "page": 2}.items()
                  if key != "total_count"}, "total_count_missing"),
                ({**info, "total_count": True, "page": 2}, "total_count_type"),
                ({**info, "total_count": mail.MAX_PAGES * mail.PAGE_SIZE + 1,
                  "page": 2}, "total_count_range"),
            ):
                list_case(Fake(list_reply={endpoint: packet([], invalid)}),
                          "invalid_payload_or_pagination", first_gate)
            for name, changed, gate in (
                ("page", 2, "page_index_mismatch"),
                ("count", 1, "page_count_mismatch"),
                ("per_page", 25, "page_size_mismatch"),
                ("total_count", 1, "total_count_inconsistent"),
            ):
                list_case(Fake(list_reply={endpoint: packet([], {**info, name: changed})}),
                          "invalid_payload_or_pagination", gate)
            # First failing gate wins: result shape precedes pagination,
            # required numeric totals precede optional page metadata.
            list_case(Fake(list_reply={endpoint: packet({}, {"page": 2})}),
                      "invalid_payload_or_pagination", "invalid_result")
            list_case(Fake(list_reply={endpoint: packet([], {**info, "total_count": None, "page": 2})}),
                      "invalid_payload_or_pagination", "total_count_type")

            # The full two-page contract is still enforced. A changed total
            # on page two is a failure, but a consistent 50+1 read completes.
            valid_item = (
                {"source": "api", "enabled": True,
                 "actions": [{"type": "forward", "value": [RECIPIENT]}],
                 "matchers": [{"type": "literal", "field": "to", "value": "m0@" + DOMAIN}]}
                if step == "rules" else {"email": RECIPIENT, "verified": None}
            )
            first_page = packet([valid_item] * mail.PAGE_SIZE, {
                "page": 1, "per_page": mail.PAGE_SIZE, "count": mail.PAGE_SIZE,
                "total_pages": 2, "total_count": mail.PAGE_SIZE + 1,
            })
            second_page = packet([valid_item], {
                "page": 2, "per_page": mail.PAGE_SIZE, "count": 1,
                "total_pages": 2, "total_count": mail.PAGE_SIZE + 1,
            })
            complete = Fake(list_pages={endpoint: [first_page, second_page]})
            complete_result = mail.observe(selected, ENV, complete)
            assert complete_result["status"] == "READ_OBSERVED"
            assert complete_result["counts"][count_key] == mail.PAGE_SIZE + 1
            assert diagnostic_key not in complete_result
            assert f"{step}_unknown_shape" not in complete_result
            assert complete.calls.count(endpoint) == 2
            safe(complete_result)
            changed_total = json.loads(second_page)
            changed_total["result_info"]["total_count"] += 1
            inconsistent_pages = Fake(list_pages={endpoint: [
                first_page, json.dumps(changed_total).encode(),
            ]})
            mismatch = mail.observe(selected, ENV, inconsistent_pages)
            assert mismatch["read"][step] == "UNKNOWN"
            assert mismatch[diagnostic_key] == "invalid_payload_or_pagination"
            assert mismatch[f"{step}_unknown_shape"] == "total_count_inconsistent"
            assert count_key not in mismatch["counts"]
            assert inconsistent_pages.calls.count(endpoint) == 2
            safe(mismatch)

            # The optional total_pages compatibility is ONLY for these two
            # endpoints. Every accepted page has an explicit, stable
            # total_count and an exact non-final/final item count.
            def omitted(items: list[dict], total: object, page: int = 1,
                        fields: tuple[str, ...] = ("page", "count", "per_page"),
                        extra: dict | None = None) -> bytes:
                info: dict = {"total_count": total}
                values = {"page": page, "count": len(items), "per_page": mail.PAGE_SIZE}
                info.update({key: values[key] for key in fields})
                info.update(extra or {})
                return packet(items, info)

            def omitted_case(pages: list[bytes], total: int,
                             error: str | None = None, calls: int | None = None) -> None:
                fixture = Fake(list_pages={endpoint: pages})
                got = mail.observe(selected, ENV, fixture)
                assert fixture.calls.count(endpoint) == (calls if calls is not None else len(pages))
                if error is None:
                    assert got["status"] == "READ_OBSERVED", got
                    assert got["read"][step] == "OBSERVED"
                    assert got["counts"][count_key] == total
                    assert diagnostic_key not in got
                    assert f"{step}_unknown_shape" not in got
                else:
                    assert got["status"] == "INCOMPLETE", got
                    assert got["read"][step] == "UNKNOWN"
                    assert got[diagnostic_key] == "invalid_payload_or_pagination"
                    assert got[f"{step}_unknown_shape"] == error, (got, error)
                    assert count_key not in got["counts"]
                assert got["write_authority"] == got["mail_arrival"] == "NOT_PROVEN"
                safe(got)

            # 0 is accepted only with an explicitly reported zero and [].
            # Includes 1..50, 51, exact multiples, remainders, and the
            # existing 100-page budget without a 101st GET.
            for total in (0, 1, 49, 50, 51, 100, 101, 150, 151,
                          mail.MAX_PAGES * mail.PAGE_SIZE):
                page_count = max(1, (total + mail.PAGE_SIZE - 1) // mail.PAGE_SIZE)
                pages = [
                    omitted(
                        [valid_item] * min(mail.PAGE_SIZE, max(0, total - (page - 1) * mail.PAGE_SIZE)),
                        total, page,
                    ) for page in range(1, page_count + 1)
                ]
                omitted_case(pages, total)

            # All three optional page/count/per_page keys may be absent,
            # but no metadata shape can silently flip across pages.
            for total in (0, 1, 51, 100):
                page_count = max(1, (total + mail.PAGE_SIZE - 1) // mail.PAGE_SIZE)
                pages = [
                    omitted(
                        [valid_item] * min(mail.PAGE_SIZE, max(0, total - (page - 1) * mail.PAGE_SIZE)),
                        total, page, fields=(),
                    ) for page in range(1, page_count + 1)
                ]
                omitted_case(pages, total)

            for items, info, gate in (
                ([], {}, "total_count_missing"),
                ([], {"total_count": True}, "total_count_type"),
                ([], {"total_count": "0"}, "total_count_type"),
                ([], {"total_count": None}, "total_count_type"),
                ([], {"total_count": -1}, "total_count_range"),
                ([], {"total_count": mail.MAX_PAGES * mail.PAGE_SIZE + 1}, "total_count_range"),
                ([], {"total_count": 1}, "total_count_inconsistent"),
                ([valid_item], {"total_count": 0}, "pagination_invalid"),
                ([valid_item] * 49, {"total_count": 51}, "total_count_inconsistent"),
                ([], {"total_count": 51}, "total_count_inconsistent"),
                ([], {"total_count": 0, "page": 2}, "page_index_mismatch"),
                ([], {"total_count": 0, "page": True}, "page_index_mismatch"),
                ([], {"total_count": 0, "count": 1}, "page_count_mismatch"),
                ([], {"total_count": 0, "count": False}, "page_count_mismatch"),
                ([], {"total_count": 0, "per_page": 25}, "page_size_mismatch"),
                ([], {"total_count": 0, "per_page": True}, "page_size_mismatch"),
            ):
                omitted_case([packet(items, info)], 0, error=gate, calls=1)

            first = omitted([valid_item] * mail.PAGE_SIZE, 51, 1)
            good_final = omitted([valid_item], 51, 2)
            # Never accept a changed total, short/overlong final page,
            # metadata contradiction or mixed total_pages presence.
            for last, gate in (
                (omitted([valid_item], 52, 2), "total_count_inconsistent"),
                (omitted([], 51, 2), "total_count_inconsistent"),
                (omitted([valid_item] * 2, 51, 2), "total_count_inconsistent"),
                (omitted([valid_item], 51, 2, extra={"page": 1}), "page_index_mismatch"),
                (omitted([valid_item], 51, 2, extra={"count": 0}), "page_count_mismatch"),
                (omitted([valid_item], 51, 2, extra={"per_page": 25}), "page_size_mismatch"),
                (omitted([valid_item], 51, 2, fields=("page", "per_page")), "pagination_invalid"),
                (omitted([valid_item], 51, 2, extra={"total_pages": 2}), "pagination_invalid"),
            ):
                omitted_case([first, last], 51, error=gate, calls=2)
            assert good_final

            # Early empty/short middle pages cannot be repaired by a
            # hypothetical future page: refusal happens before the next GET.
            first101 = omitted([valid_item] * mail.PAGE_SIZE, 101, 1)
            for short in (omitted([], 101, 2), omitted([valid_item] * 49, 101, 2)):
                omitted_case([first101, short], 101,
                             error="total_count_inconsistent", calls=2)
            second101 = omitted([valid_item] * mail.PAGE_SIZE, 101, 2)
            omitted_case([first101, second101, omitted([], 101, 3)], 101,
                         error="total_count_inconsistent", calls=3)

            # Present first page -> absent later page is a refusal: never
            # downgrade the original strict mode mid-enumeration.
            omitted_case([first_page, good_final], 51,
                         error="total_pages_missing", calls=2)

            # Item validators run on the same reader after full-count proof.
            list_case(Fake(list_reply={endpoint: omitted([{}], 1)}), shape)

            # main() reads the exact synthetic production path, but prints
            # only the closed results (never token/account/domain/contact).
            saved_opener = mail.safe_opener
            saved_env = dict(os.environ)
            try:
                mail.safe_opener = lambda endpoint=endpoint: Fake(list_reply={
                    endpoint: omitted([], 0),
                })
                os.environ.clear()
                os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
                output = io.StringIO()
                with redirect_stdout(output):
                    assert mail.main() == 0
                closed = json.loads(output.getvalue())
                assert closed["status"] == "READ_OBSERVED"
                assert closed["counts"][count_key] == 0
                assert diagnostic_key not in closed
                assert f"{step}_unknown_shape" not in closed
                safe(closed)
            finally:
                mail.safe_opener = saved_opener
                os.environ.clear()
                os.environ.update(saved_env)

            # Same first-rejection contract applies on subsequent pages, not
            # merely the initial empty-list fixture. It changes no GET count.
            for broken_info, first_gate in (
                ({key: value for key, value in json.loads(second_page)["result_info"].items()
                  if key != "total_pages"}, "total_pages_missing"),
                ({**json.loads(second_page)["result_info"], "total_pages": False},
                 "total_pages_type"),
                ({**json.loads(second_page)["result_info"],
                  "total_pages": mail.MAX_PAGES + 1}, "total_pages_range"),
                ({key: value for key, value in json.loads(second_page)["result_info"].items()
                  if key != "total_count"}, "total_count_missing"),
                ({**json.loads(second_page)["result_info"], "total_count": "51"},
                 "total_count_type"),
                ({**json.loads(second_page)["result_info"],
                  "total_count": mail.MAX_PAGES * mail.PAGE_SIZE + 1},
                 "total_count_range"),
            ):
                bad_second = packet([valid_item], broken_info)
                failing = Fake(list_pages={endpoint: [first_page, bad_second]})
                actual = mail.observe(selected, ENV, failing)
                assert actual["read"][step] == "UNKNOWN"
                assert actual[diagnostic_key] == "invalid_payload_or_pagination"
                assert actual[f"{step}_unknown_shape"] == first_gate
                assert count_key not in actual["counts"]
                assert failing.calls.count(endpoint) == 2
                safe(actual)

            # A local item validator has its pre-existing distinct reason,
            # not a payload/pagination gate fabricated by this diagnostic.
            list_case(Fake(overrides={endpoint: [{}]}), shape)
            list_case(Fake(list_unexpected=endpoint), "unclassified")

            # An explicit refusal remains DENIED and has NO diagnostic reason.
            for refused in (401, 403):
                denied = mail.observe(selected, ENV, Fake(list_http=(endpoint, refused)))
                assert denied["read"][step] == "DENIED"
                assert diagnostic_key not in denied
                assert f"{step}_unknown_shape" not in denied
                assert "zone_unknown_reason" not in denied
                safe(denied)

            # Legitimate empty list is OBSERVED(0), including Cloudflare's
            # zero-page form; never speculate that it is a missing permission.
            for payload in (wrap([]),):
                completed = mail.observe(selected, ENV, Fake(list_reply={endpoint: payload}))
                assert completed["status"] == "READ_OBSERVED"
                assert completed["counts"][count_key] == 0
                assert diagnostic_key not in completed
                assert f"{step}_unknown_shape" not in completed
                safe(completed)
            empty_zero_page = json.loads(wrap([]))
            empty_zero_page["result_info"]["total_pages"] = 0
            completed = mail.observe(selected, ENV, Fake(
                list_reply={endpoint: json.dumps(empty_zero_page).encode()}))
            assert completed["status"] == "READ_OBSERVED"
            assert completed["counts"][count_key] == 0
            assert diagnostic_key not in completed
            assert f"{step}_unknown_shape" not in completed
            safe(completed)

        # Exercise the actual closed stdout path for BOTH step diagnostics,
        # with the real production observe/main and synthetic injected opener.
        for step, endpoint in (
            ("rules", f"/zones/{ZONE}/email/routing/rules"),
            ("addresses", f"/accounts/{ACCOUNT}/email/routing/addresses"),
        ):
            saved_opener = mail.safe_opener
            saved_env = dict(os.environ)
            try:
                mail.safe_opener = lambda endpoint=endpoint: Fake(list_transport=endpoint)
                os.environ.clear()
                os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
                output = io.StringIO()
                with redirect_stdout(output):
                    assert mail.main() == 2
                closed = json.loads(output.getvalue())
                assert closed[f"{step}_unknown_reason"] == "transport"
                assert "zone_unknown_reason" not in closed
                safe(closed)
            finally:
                mail.safe_opener = saved_opener
                os.environ.clear()
                os.environ.update(saved_env)

        # The actual main()->observe()->_request()->_list() output also
        # carries ONLY the fixed structural gate, never a raw response.
        for step, endpoint in (
            ("rules", f"/zones/{ZONE}/email/routing/rules"),
            ("addresses", f"/accounts/{ACCOUNT}/email/routing/addresses"),
        ):
            saved_opener = mail.safe_opener
            saved_env = dict(os.environ)
            missing_info = json.loads(wrap([]))
            missing_info.pop("result_info")
            try:
                mail.safe_opener = lambda endpoint=endpoint: Fake(list_reply={
                    endpoint: json.dumps(missing_info).encode(),
                })
                os.environ.clear()
                os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
                stream = io.StringIO()
                with redirect_stdout(stream):
                    assert mail.main() == 2
                closed = json.loads(stream.getvalue())
                assert closed[f"{step}_unknown_reason"] == "invalid_payload_or_pagination"
                assert closed[f"{step}_unknown_shape"] == "pagination_missing"
                other = "addresses" if step == "rules" else "rules"
                assert f"{other}_unknown_shape" not in closed
                assert "zone_unknown_reason" not in closed
                safe(closed)
            finally:
                mail.safe_opener = saved_opener
                os.environ.clear()
                os.environ.update(saved_env)

        # The actual main()->observe()->_list() PUBLIC JSON distinguishes
        # the remaining strict invalid-total conditions for both list endpoints.
        # This does not access a live provider or reveal a numeric value.
        for step, endpoint in (
            ("rules", f"/zones/{ZONE}/email/routing/rules"),
            ("addresses", f"/accounts/{ACCOUNT}/email/routing/addresses"),
        ):
            basic = json.loads(wrap([]))["result_info"]
            for info_value, gate in (
                ({**basic, "total_pages": True}, "total_pages_type"),
                ({**basic, "total_pages": -1}, "total_pages_range"),
                ({key: value for key, value in basic.items() if key != "total_count"},
                 "total_count_missing"),
                ({**basic, "total_count": "0"}, "total_count_type"),
                ({**basic, "total_count": mail.MAX_PAGES * mail.PAGE_SIZE + 1},
                 "total_count_range"),
            ):
                saved_opener = mail.safe_opener
                saved_env = dict(os.environ)
                try:
                    mail.safe_opener = lambda endpoint=endpoint, info_value=info_value: Fake(
                        list_reply={endpoint: packet([], info_value)},
                    )
                    os.environ.clear()
                    os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
                    output = io.StringIO()
                    with redirect_stdout(output):
                        assert mail.main() == 2
                    closed = json.loads(output.getvalue())
                    assert closed[f"{step}_unknown_reason"] == "invalid_payload_or_pagination"
                    assert closed[f"{step}_unknown_shape"] == gate
                    assert closed["read"][step] == "UNKNOWN"
                    assert "zone_unknown_reason" not in closed
                    other = "addresses" if step == "rules" else "rules"
                    assert f"{other}_unknown_shape" not in closed
                    safe(closed)
                finally:
                    mail.safe_opener = saved_opener
                    os.environ.clear()
                    os.environ.update(saved_env)

        # Exercise main() with synthetic *valid* account and mocked opener
        # to establish that its actual public JSON retains only the enum.
        prior_opener = mail.safe_opener
        saved_env = dict(os.environ)
        try:
            mail.safe_opener = lambda: Fake(zone_transport=True)
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            output = io.StringIO()
            with redirect_stdout(output):
                assert mail.main() == 2
            exposed = json.loads(output.getvalue())
            assert exposed["zone_unknown_reason"] == "transport"
            safe(exposed)
        finally:
            mail.safe_opener = prior_opener
            os.environ.clear()
            os.environ.update(saved_env)

        result = mail.observe(selected, ENV, Fake(bad=f"/zones/{ZONE}/dns_records"))
        assert result["status"] == "INCOMPLETE" and result["read"]["dns"] == "UNKNOWN"
        safe(result)

        # Main entry only with INVALID input; never execute a live network
        # call from this synthetic CI test.
        preserved = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            os.environ["CLOUDFLARE_ACCOUNT_ID"] = "invalid"
            stream = io.StringIO()
            with redirect_stdout(stream):
                assert mail.main() == 2
            safe(json.loads(stream.getvalue()))
        finally:
            os.environ.clear()
            os.environ.update(preserved)

    workflow = (ROOT / ".github/workflows/probe-dev-mail-routing.yml").read_text(encoding="utf-8")
    assert "      domain:\n" in workflow and "domain_sha256:" not in workflow
    assert "CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}" in workflow
    assert "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in workflow
    assert "GH_TOKEN: ${{ github.token }}\n          CLOUDFLARE_API_TOKEN" not in workflow
    assert "github.actor_id == '40359643'" in workflow
    assert "github.triggering_actor == 'roccho-dev'" in workflow
    assert "inputs.domain" not in workflow
    assert "environment: dev-projection" in workflow
    test_transport_no_redirect_no_proxy()
    print("mail routing read selftest: PASS; GET-only, safe transport/schema/metadata")


if __name__ == "__main__":
    main()
