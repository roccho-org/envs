#!/usr/bin/env python3
"""One bounded, read-only Mail M0 Cloudflare preflight; no provider effects.

Dispatch domain is read from GITHUB_EVENT_PATH, never argv or a logged env.
Only dev-projection's existing token/account inputs are consumed. The result is
a closed non-secret summary: no API response body, domain, token, account or
zone identifier, email, request URL, exception message or traceback escapes.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

API = "https://api.cloudflare.com/client/v4"
ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
STEPS = ("token", "zone", "dns", "routing", "routing_dns", "rules", "catch_all", "addresses")
MAX_RESPONSE = 1_000_000
MAX_PAGES = 100
PAGE_SIZE = 50
# Only one bounded, non-secret reason for an UNKNOWN zone selection. Never
# include response bodies, HTTP codes, identifiers, request URLs or exceptions.
ZONE_UNKNOWN_REASONS = frozenset((
    "transport", "http_other", "invalid_payload_or_pagination",
    "zero_match", "multiple_match", "owner_or_id_mismatch", "unclassified",
))
# A structural gate rejected by THIS client's strict list parser.
# Expose only on a rules/addresses invalid_payload_or_pagination UNKNOWN.
# Never emit field values, counts from rejected lists, URLs or HTTP codes.
LIST_UNKNOWN_SHAPES = frozenset((
    "response_size", "invalid_json", "invalid_envelope", "invalid_result",
    "nonobject_item", "pagination_missing", "pagination_invalid",
    "total_pages_missing", "total_pages_type", "total_pages_range",
    "total_count_missing", "total_count_type", "total_count_range",
    "page_index_mismatch", "page_size_mismatch", "page_count_mismatch",
    "total_count_inconsistent",
))
Opener = Callable[..., Any]


class ReadFailure(Exception):
    def __init__(self, state: str = "UNKNOWN", reason: str = "invalid_payload_or_pagination",
                 shape: str | None = None) -> None:
        self.state = state
        self.reason = reason if state == "UNKNOWN" and reason in ZONE_UNKNOWN_REASONS else None
        self.shape = shape if self.reason == "invalid_payload_or_pagination" and shape in LIST_UNKNOWN_SHAPES else None


# Bounded gate names; no item value/source/identifier is emitted.
RULE_ITEM_GATES = frozenset((
    "enabled_unknown", "source_unknown", "actions_unknown",
    "matchers_unknown", "matcher_type_invalid",
    "matcher_field_invalid", "matcher_value_invalid",
))


class ItemShapeFailure(ReadFailure):
    """A local rules/addresses item failed the ordered schema checks."""

    def __init__(self, gate: str | None = None) -> None:
        super().__init__()
        self.gate = gate if gate in RULE_ITEM_GATES else None


class DenyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        # Refuse both same-origin and cross-origin 30x; no Bearer forwarding.
        return None


def safe_opener(https_handler: urllib.request.BaseHandler | None = None) -> Opener:
    # An explicit empty ProxyHandler suppresses the OS/ambient HTTPS_PROXY,
    # HTTP_PROXY and no_proxy lookup used by urllib's default urlopen.
    # The test-only handler exercises the real urllib redirect/proxy chain
    # without a socket or a provider request.
    handler = https_handler or urllib.request.HTTPSHandler(context=ssl.create_default_context())
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), DenyRedirect(), handler).open


def domain_from_event(path: str) -> str:
    # This is an explicitly non-secret selected-domain locator in native
    # workflow_dispatch metadata. It is NEVER used as a credential, emitted
    # in stdout/stderr, or expanded by an Actions run-step environment.
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        value = event["inputs"]["domain"]
        if not isinstance(value, str):
            raise ValueError()
        domain = value.lower()
        if (len(domain) > 253 or len(domain) < 4 or domain != value.strip().lower()
                or "." not in domain or any(not LABEL.fullmatch(part) for part in domain.split("."))):
            raise ValueError()
        return domain
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise ReadFailure() from None


def private_inputs(event_path: str, environ: Mapping[str, str]) -> tuple[str, str, str]:
    # Both Cloudflare inputs use EXISTING dev-projection native GitHub slots.
    # GitHub Variables are not Secret-masked; account is allowed here only as
    # a NON-SECRET operational locator under the bounded P v2 exception.
    domain = domain_from_event(event_path)
    account = environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = environ.get("CLOUDFLARE_API_TOKEN", "")
    if not ACCOUNT.fullmatch(account) or not token or len(token) > 4096 or token != token.strip():
        raise ReadFailure()
    return domain, account, token


def _request(opener: Opener, token: str, path: str, params: Mapping[str, object] | None = None) -> Any:
    query = urllib.parse.urlencode(params or {})
    url = API + path + ("?" + query if query else "")
    req = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        method="GET",
    )
    try:
        with opener(req, timeout=12) as response:
            if getattr(response, "status", 200) != 200:
                raise ReadFailure("DENIED" if response.status in (401, 403) else "UNKNOWN", "http_other")
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ReadFailure(shape="response_size")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ReadFailure(shape="invalid_json") from None
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ReadFailure(shape="invalid_envelope")
        if not isinstance(payload.get("result"), (dict, list)):
            raise ReadFailure(shape="invalid_result")
        return payload
    except urllib.error.HTTPError as error:
        raise ReadFailure("DENIED" if error.code in (401, 403) else "UNKNOWN", "http_other") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ReadFailure(reason="transport") from None
    except (ValueError, TypeError, UnicodeError):
        raise ReadFailure(reason="invalid_payload_or_pagination") from None


def _list(opener: Opener, token: str, path: str,
          params: Mapping[str, object] | None = None, *,
          allow_missing_total_pages: bool = False) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    expected_total: int | None = None
    omitted_pages: bool | None = None
    omitted_optional_keys: frozenset[str] | None = None
    for page in range(1, MAX_PAGES + 1):
        args = {**(params or {}), "page": page, "per_page": PAGE_SIZE}
        payload = _request(opener, token, path, args)
        info = payload.get("result_info")
        batch = payload["result"]
        # First rejecting condition wins. These are diagnostics, not new
        # acceptance rules: optional page/count/per_page still default as
        # before; result_info with int totals and full-page agreement remains
        # mandatory. A valid empty result remains an observed zero.
        if not isinstance(batch, list):
            raise ReadFailure(shape="invalid_result")
        if any(not isinstance(item, dict) for item in batch):
            raise ReadFailure(shape="nonobject_item")
        if info is None:
            raise ReadFailure(shape="pagination_missing")
        if not isinstance(info, dict):
            raise ReadFailure(shape="pagination_invalid")
        # Existing strict total_pages-present behavior is unchanged for all
        # callers. Only rules/addresses opt into the Cloudflare-optional
        # total_pages compatibility path; this does NOT waive full enumeration.
        missing_pages = "total_pages" not in info
        if missing_pages and not allow_missing_total_pages:
            raise ReadFailure(shape="total_pages_missing")
        if allow_missing_total_pages:
            if omitted_pages is None:
                omitted_pages = missing_pages
            elif omitted_pages != missing_pages:
                # Do not silently switch modes and discard a previous-page
                # completeness check if metadata appears/disappears.
                raise ReadFailure(shape="pagination_invalid" if omitted_pages else "total_pages_missing")
        if not missing_pages:
            total_pages = info["total_pages"]
            if type(total_pages) is not int:  # bool is not an integer total
                raise ReadFailure(shape="total_pages_type")
            if total_pages < 0 or total_pages > MAX_PAGES:
                raise ReadFailure(shape="total_pages_range")
        if "total_count" not in info:
            raise ReadFailure(shape="total_count_missing")
        total_count = info["total_count"]
        if type(total_count) is not int:  # bool is not an integer total
            raise ReadFailure(shape="total_count_type")
        if total_count < 0 or total_count > MAX_PAGES * PAGE_SIZE:
            raise ReadFailure(shape="total_count_range")
        if missing_pages:
            # A full non-final page and exactly sized final page are necessary
            # even when Cloudflare omits total_pages. No short first-page or
            # early-empty heuristic is sufficient to prove completeness.
            total_pages = (total_count + PAGE_SIZE - 1) // PAGE_SIZE
            if total_pages > MAX_PAGES:
                raise ReadFailure(shape="total_count_range")
            keys = frozenset(k for k in ("page", "count", "per_page") if k in info)
            if omitted_optional_keys is None:
                omitted_optional_keys = keys
            elif keys != omitted_optional_keys:
                raise ReadFailure(shape="pagination_invalid")
            # Bool/float equal to an integer is not valid metadata.
            for key, expected, shape in (
                ("page", page, "page_index_mismatch"),
                ("count", len(batch), "page_count_mismatch"),
                ("per_page", PAGE_SIZE, "page_size_mismatch"),
            ):
                if key in info and (type(info[key]) is not int or info[key] != expected):
                    raise ReadFailure(shape=shape)
        else:
            # Retain the previous strict total_pages-present acceptance path.
            if info.get("page", page) != page:
                raise ReadFailure(shape="page_index_mismatch")
            if info.get("count", len(batch)) != len(batch):
                raise ReadFailure(shape="page_count_mismatch")
            if info.get("per_page", PAGE_SIZE) != PAGE_SIZE:
                raise ReadFailure(shape="page_size_mismatch")
        # Cloudflare may express an empty list as total_pages=0 or 1.
        # For omitted total_pages, a proven total_count=0 and actual [] is
        # the only legal zero; nothing is inferred from an empty first page.
        if page == 1 and total_count == 0 and total_pages == 0 and not batch:
            return []
        if total_pages == 0:
            raise ReadFailure(shape="pagination_invalid")
        if missing_pages:
            remaining = total_count - (page - 1) * PAGE_SIZE
            required = min(PAGE_SIZE, remaining)
            if required <= 0 or len(batch) != required:
                raise ReadFailure(shape="total_count_inconsistent")
        if expected_total is not None and total_count != expected_total:
            raise ReadFailure(shape="total_count_inconsistent")
        expected_total = total_count
        results.extend(batch)
        if page == total_pages:
            if len(results) != total_count:
                raise ReadFailure(shape="total_count_inconsistent")
            return results
        if page > total_pages:
            raise ReadFailure(shape="page_index_mismatch")
    raise ReadFailure(shape="pagination_invalid")


def _single(opener: Opener, token: str, path: str) -> dict[str, Any]:
    value = _request(opener, token, path)["result"]
    if not isinstance(value, dict):
        raise ReadFailure()
    return value


def _empty() -> dict[str, Any]:
    return {
        "kind": "envs.mailRoutingRead.v1",
        "status": "INCOMPLETE",
        "read": {step: "UNKNOWN" for step in STEPS},
        "facts": {},
        "counts": {},
        "write_authority": "NOT_PROVEN",
        "mail_arrival": "NOT_PROVEN",
    }


def observe(event_path: str, environ: Mapping[str, str], opener: Opener | None = None) -> dict[str, Any]:
    output = _empty()
    try:
        domain, account, token = private_inputs(event_path, environ)
    except ReadFailure:
        return output
    if opener is None:
        opener = safe_opener()

    def check(step: str, fetch: Callable[[], Any]) -> Any | None:
        try:
            result = fetch()
        except ReadFailure as failure:
            output["read"][step] = failure.state
            if failure.state == "UNKNOWN":
                if step == "zone":
                    output["zone_unknown_reason"] = failure.reason or "unclassified"
                elif step in ("rules", "addresses"):
                    # Shape means "rejected by this LOCAL item validator",
                    # never "the provider returned a bad resource".
                    shape = "rule_item_shape" if step == "rules" else "address_item_shape"
                    reason = shape if isinstance(failure, ItemShapeFailure) else failure.reason
                    if reason not in ("transport", "http_other", "invalid_payload_or_pagination", shape):
                        reason = "unclassified"
                    output[f"{step}_unknown_reason"] = reason
                    if (step == "rules" and reason == "rule_item_shape"
                            and isinstance(failure, ItemShapeFailure) and failure.gate is not None):
                        output["rules_unknown_gate"] = failure.gate
                    if (reason == "invalid_payload_or_pagination"
                            and failure.shape in LIST_UNKNOWN_SHAPES):
                        # Exactly one structural gate; never attach to local
                        # item-shape refusal, DENIED, another step or success.
                        output[f"{step}_unknown_shape"] = failure.shape
            return None
        except Exception:
            # Fail closed even for malformed provider/opener implementations.
            output["read"][step] = "UNKNOWN"
            if step in ("zone", "rules", "addresses"):
                output[f"{step}_unknown_reason"] = "unclassified"
            return None
        output["read"][step] = "OBSERVED"
        return result

    def read_token() -> dict[str, Any]:
        data = _single(opener, token, "/user/tokens/verify")
        if data.get("status") not in ("active", "disabled", "expired", "inactive"):
            raise ReadFailure()
        return data

    verification = check("token", read_token)
    if verification is None:
        return output
    output["facts"]["token_active"] = verification["status"] == "active"
    if not output["facts"]["token_active"]:
        return output

    # Native Cloudflare account and selected domain filters are sent together.
    # Do not enumerate other zones just to hide an ordinary non-secret selector.
    zones = check("zone", lambda: _list(opener, token, "/zones", {
        "name": domain, "account.id": account, "match": "all",
    }))
    if zones is None:
        # Preserve HTTP DENIED, do not silently demote it to UNKNOWN.
        return output
    if len(zones) != 1:
        output["read"]["zone"] = "UNKNOWN"
        output["zone_unknown_reason"] = "zero_match" if not zones else "multiple_match"
        return output
    zone = zones[0]
    owner = zone.get("account")
    if (zone.get("name") != domain or not isinstance(owner, dict)
            or owner.get("id") != account or not ACCOUNT.fullmatch(str(zone.get("id", "")))):
        output["read"]["zone"] = "UNKNOWN"
        output["zone_unknown_reason"] = "owner_or_id_mismatch"
        return output

    zone_id = zone["id"]
    # Each capability is independently observed. Failure/403 is not absence or
    # evidence of missing Write permission; never switch account/zone/token.
    def read_dns() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/zones/{zone_id}/dns_records")
        if any(not isinstance(row.get("type"), str) or not row["type"].strip() for row in rows):
            raise ReadFailure()
        return rows

    dns = check("dns", read_dns)
    if dns is not None:
        output["counts"]["dns"] = len(dns)
        output["facts"]["mx_present"] = any(x.get("type") == "MX" for x in dns)
        output["counts"]["mx"] = sum(x.get("type") == "MX" for x in dns)
        output["counts"]["txt"] = sum(x.get("type") == "TXT" for x in dns)

    def read_routing() -> dict[str, Any]:
        data = _single(opener, token, f"/zones/{zone_id}/email/routing")
        if (type(data.get("enabled")) is not bool
                or data.get("status") not in (
                    "ready", "unconfigured", "misconfigured", "misconfigured/locked", "unlocked",
                )):
            raise ReadFailure()
        return data

    routing = check("routing", read_routing)
    if routing is not None:
        output["facts"]["routing_ready"] = routing["status"] == "ready"
        output["facts"]["routing_enabled"] = routing["enabled"]

    def routing_dns_read() -> list[dict[str, Any]]:
        payload = _request(opener, token, f"/zones/{zone_id}/email/routing/dns")
        records = payload["result"]
        info = payload.get("result_info")
        if (not isinstance(records, list)
                or any(not isinstance(item, dict) or not isinstance(item.get("type"), str)
                       or not item["type"].strip() for item in records)
                or (isinstance(info, dict) and info.get("total_count", len(records)) != len(records))):
            raise ReadFailure()
        return records

    routing_dns = check("routing_dns", routing_dns_read)
    if routing_dns is not None:
        output["counts"]["routing_dns_records"] = len(routing_dns)

    def read_rules() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/zones/{zone_id}/email/routing/rules",
                     allow_missing_total_pages=True)
        for row in rows:
            # Fixed order of the FIRST rejecting local gate. Read-side
            # source/provenance must never use the write-side api default.
            if type(row.get("enabled")) is not bool:
                raise ItemShapeFailure("enabled_unknown")
            if row.get("source") not in ("api", "wrangler"):
                raise ItemShapeFailure("source_unknown")
            actions = row.get("actions")
            if not isinstance(actions, list) or not actions:
                raise ItemShapeFailure("actions_unknown")
            for action in actions:
                if (not isinstance(action, dict)
                        or action.get("type") not in ("drop", "forward", "worker")):
                    raise ItemShapeFailure("actions_unknown")
                values = action.get("value")
                if (values is not None and (
                        not isinstance(values, list)
                        or any(not isinstance(v, str) or not v.strip() for v in values)
                )):
                    raise ItemShapeFailure("actions_unknown")
                if action["type"] in ("forward", "worker") and (
                        not isinstance(values, list) or not values
                ):
                    raise ItemShapeFailure("actions_unknown")
            matchers = row.get("matchers")
            if (not isinstance(matchers, list) or not matchers
                    or any(not isinstance(m, dict) for m in matchers)):
                raise ItemShapeFailure("matchers_unknown")
            for matcher in matchers:
                kind = matcher.get("type")
                if kind not in ("all", "literal"):
                    raise ItemShapeFailure("matcher_type_invalid")
                # Native all matcher accepts omitted field/value. Literal
                # receiver must prove field=to and a nonempty string value.
                if kind == "literal" or "field" in matcher:
                    if matcher.get("field") != "to":
                        raise ItemShapeFailure("matcher_field_invalid")
                if kind == "literal" or "value" in matcher:
                    value = matcher.get("value")
                    # Native all.value is optional string (max 90, no minimum);
                    # a literal recipient alone requires a nonblank target.
                    if (not isinstance(value, str) or len(value) > 90
                            or (kind == "literal" and not value.strip())):
                        raise ItemShapeFailure("matcher_value_invalid")
        return rows

    rules = check("rules", read_rules)
    if rules is not None:
        output["counts"]["rules"] = len(rules)
        output["counts"]["enabled_rules"] = sum(x.get("enabled") is True for x in rules)
        output["counts"]["wrangler_rules"] = sum(x.get("source") == "wrangler" for x in rules)

    def read_catch() -> dict[str, Any]:
        data = _single(opener, token, f"/zones/{zone_id}/email/routing/rules/catch_all")
        if type(data.get("enabled")) is not bool:
            raise ReadFailure()
        return data

    catch = check("catch_all", read_catch)
    if catch is not None:
        output["facts"]["catch_all_enabled"] = catch["enabled"]

    def read_addresses() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/accounts/{account}/email/routing/addresses",
                     allow_missing_total_pages=True)
        for row in rows:
            value = row.get("verified", ...)
            if (not isinstance(row.get("email"), str) or not row["email"]
                    or (value is not None and (
                        not isinstance(value, str)
                        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T[^\s]+", value) is None
                    ))):
                raise ItemShapeFailure()
        return rows

    addresses = check("addresses", read_addresses)
    if addresses is not None:
        output["counts"]["account_destinations"] = len(addresses)
        output["counts"]["verified_destinations"] = sum(x["verified"] is not None for x in addresses)

    if all(output["read"][key] == "OBSERVED" for key in STEPS):
        output["status"] = "READ_OBSERVED"
    return output


def main() -> int:
    # No traceback, provider response, identifier, domain, or exception details.
    try:
        result = observe(os.environ.get("GITHUB_EVENT_PATH", ""), os.environ)
    except Exception:
        result = _empty()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["status"] == "READ_OBSERVED" else 2


if __name__ == "__main__":
    sys.exit(main())
