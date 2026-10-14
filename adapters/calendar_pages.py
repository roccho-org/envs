#!/usr/bin/env python3
"""One bounded Cloudflare Pages effect: roccho-dev/apps family calendar only.

Never prints API credentials, provider bodies, or child stderr.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

APPS_REPO = "roccho-dev/apps"
ENVS_REPO = "roccho-org/envs"
CONTROL_ISSUE = 69
CONTROLLER_ID = 40359643
PROJECT = "roccho-family-calendar-2026"
BRANCH = "proposals"
SOURCE_DIR = Path("calendar-source/packages/calendar/src")
RUN_PATHS = {".github/workflows/calendar-ci.yml", ".github/workflows/nix-check.yml"}
SHA = re.compile(r"^[0-9a-f]{40}$")
COMMAND = re.compile(r"^/deploy-calendar ([0-9a-f]{40})$")
ACCOUNT = re.compile(r"^[0-9a-f]{32}$")


class Refusal(Exception):
    pass


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Refusal(why)


def get_comment_sha(event: dict) -> str:
    require(event.get("repository", {}).get("full_name") == ENVS_REPO, "BAD_REPOSITORY")
    require(event.get("issue", {}).get("number") == CONTROL_ISSUE
            and not event["issue"].get("pull_request"), "BAD_ISSUE")
    require(event.get("comment", {}).get("user", {}).get("id") == CONTROLLER_ID, "BAD_ACTOR")
    match = COMMAND.fullmatch(event.get("comment", {}).get("body", ""))
    require(match is not None, "BAD_COMMAND")
    return match.group(1)


def validate_events(path: Path) -> None:
    require(path.is_file() and path.stat().st_size <= 256_000, "BAD_JSONL_FILE")
    lines = path.read_text(encoding="utf-8").splitlines()
    require(len(lines) <= 10_000, "TOO_MANY_EVENTS")
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            require(type(item) is dict and set(item).issubset({"date", "title", "holiday"}),
                    "BAD_EVENT_SHAPE")
            require(type(item.get("date")) is str and
                    re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["date"]), "BAD_EVENT_DATE")
            dt.date.fromisoformat(item["date"])
            require(type(item.get("title")) is str and 0 < len(item["title"]) <= 240,
                    "BAD_EVENT_TITLE")
            require("holiday" not in item or type(item["holiday"]) is bool, "BAD_HOLIDAY")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise Refusal("INVALID_JSONL") from exc


def request_json(url: str, token: str | None = None) -> tuple[int, dict]:
    headers = {"Accept": "application/json", "User-Agent": "calendar-pages-boundary/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        # Only the status is retained. Never read/log the provider body.
        return exc.code, {}


def attest(app_sha: str, root: Path, token: str) -> None:
    require(SHA.fullmatch(app_sha) is not None, "BAD_SOURCE_SHA")
    toolbin = os.getenv("ENVS_EFFECT_BIN", "")
    require(re.fullmatch(r"/nix/store/[a-z0-9]{32}-envs-effect-toolchain/bin", toolbin) is not None,
            "INVALID_PROVIDED_TOOL")
    git = str(Path(toolbin) / "git")
    require(Path(git).is_file(), "MISSING_GIT")
    actual = subprocess.run([git, "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=15)
    require(actual.returncode == 0 and actual.stdout.strip() == app_sha, "SOURCE_MISMATCH")
    path = root / "packages/calendar/src"
    require(path.is_dir() and {p.name for p in path.iterdir()} == {"index.html", "events.jsonl"},
            "SOURCE_FILE_SET_DIFFERS")
    require((path / "index.html").read_bytes().lstrip().startswith(b"<!doctype html>"),
            "NOT_STATIC_HTML")
    validate_events(path / "events.jsonl")
    headers = {"Authorization": "Bearer " + token, "User-Agent": "calendar-pages-boundary/1"}
    uri = f"https://api.github.com/repos/{APPS_REPO}/actions/runs?head_sha={app_sha}&per_page=100"
    with urllib.request.urlopen(urllib.request.Request(uri, headers=headers), timeout=25) as response:
        data = json.load(response)
    runs = data.get("workflow_runs", [])
    present = {run.get("path") for run in runs
               if run.get("head_sha") == app_sha and run.get("conclusion") == "success"
               and run.get("event") == "pull_request"}
    require(RUN_PATHS <= present, "APPS_CI_NOT_GREEN")


def pages_project(account: str, token: str) -> tuple[int, dict]:
    return request_json(f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{PROJECT}",
                        token)


def public_readback(host: str, path: Path) -> None:
    require(re.fullmatch(r"[a-z0-9-]+\.pages\.dev", host) is not None,
            "BAD_PROVIDER_HOST")
    for filename in ("index.html", "events.jsonl"):
        expected = (path / filename).read_bytes()
        match = False
        for attempt in range(8):
            try:
                url = f"https://{host}/{filename}?verify={int(time.time())}-{attempt}"
                req = urllib.request.Request(url, headers={"User-Agent": "calendar-pages-readback/1"})
                with urllib.request.urlopen(req, timeout=20) as response:
                    match = (response.status == 200 and response.read() == expected)
            except (OSError, urllib.error.URLError):
                match = False
            if match:
                break
            time.sleep(3)
        require(match, "PUBLIC_READBACK_MISMATCH_" + filename)


def deploy(app_sha: str, root: Path) -> None:
    require(SHA.fullmatch(app_sha) is not None, "BAD_DEPLOY_SHA")
    account, token = os.getenv("CLOUDFLARE_ACCOUNT_ID", ""), os.getenv("CLOUDFLARE_API_TOKEN", "")
    toolbin = os.getenv("ENVS_EFFECT_BIN", "")
    require(ACCOUNT.fullmatch(account) is not None and bool(token), "MISSING_PROVIDER_INPUT")
    require(re.fullmatch(r"/nix/store/[a-z0-9]{32}-envs-effect-toolchain/bin", toolbin) is not None,
            "INVALID_PROVIDED_TOOL")
    site = root / "packages/calendar/src"
    require(site.is_dir(), "MISSING_SITE")
    validate_events(site / "events.jsonl")
    wrangler = str(Path(toolbin) / "wrangler")
    require(Path(wrangler).is_file(), "MISSING_WRANGLER")
    status, project = pages_project(account, token)
    require(status in (200, 404), "PROJECT_PREFLIGHT_FAILED")
    if status == 404:
        created = subprocess.run([wrangler, "pages", "project", "create", PROJECT,
                                  "--production-branch=" + BRANCH],
                                 capture_output=True, timeout=100, check=False)
        require(created.returncode == 0, "PROJECT_CREATE_FAILED")
        status, project = pages_project(account, token)
    require(status == 200 and project.get("success") is True
            and type(project.get("result")) is dict, "PROJECT_NOT_READABLE")
    value = project["result"]
    require(value.get("name") == PROJECT and value.get("production_branch") == BRANCH,
            "PROJECT_IDENTITY_DIFFERS")
    deployed = subprocess.run([wrangler, "pages", "deploy", str(site),
                               "--project-name=" + PROJECT, "--branch=" + BRANCH,
                               "--commit-hash=" + app_sha],
                              capture_output=True, timeout=180, check=False)
    require(deployed.returncode == 0, "PAGES_DEPLOY_FAILED")
    status, project = pages_project(account, token)
    require(status == 200 and project.get("success") is True
            and project.get("result", {}).get("name") == PROJECT, "PROJECT_READBACK_FAILED")
    host = project["result"].get("subdomain", "")
    public_readback(host, site)
    print(f"CALENDAR_PAGES=PASS app_sha={app_sha} url=https://{host}/", flush=True)


def main() -> int:
    try:
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        if command == "select":
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
            sha = get_comment_sha(event)
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
                out.write("app_sha=" + sha + "\n")
            print("CALENDAR_REQUEST=ACCEPTED")
        elif command == "verify":
            attest(os.environ["APP_SHA"], Path("calendar-source"), os.environ["GH_TOKEN"])
            print("CALENDAR_SOURCE=CI_GREEN")
        elif command == "deploy":
            deploy(os.environ["APP_SHA"], Path("calendar-source"))
        else:
            raise Refusal("UNKNOWN_COMMAND")
    except (Refusal, KeyError, OSError, ValueError, urllib.error.URLError, subprocess.TimeoutExpired) as exc:
        print("CALENDAR_PAGES=RED " + (str(exc) if isinstance(exc, Refusal) else type(exc).__name__),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
