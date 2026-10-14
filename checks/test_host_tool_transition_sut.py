#!/usr/bin/env python3
"""Disposable filesystem SUT for Host Tool transitions; NEVER a real Nix/Host executor.

SOURCE tests actually change only temporary generation symlinks; the actual
nix-env, OCI, and Native VM operations are separately proved by Windows/resources.
No credential, Target access, network, provider, runtime ledger, or subprocess.
"""
from __future__ import annotations

import copy
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
from host_tool_guard import judge  # noqa: E402
from host_tool_continuation import evaluate  # noqa: E402
from test_host_tool_guard import context  # noqa: E402
from test_host_tool_continuation import facts, receiver  # noqa: E402

STORE0 = "/nix/store/" + "a" * 32 + "-older-tool"
STORE1 = "/nix/store/" + "b" * 32 + "-chosen-tool"


class DisposableHost:
    """No source outside a TemporaryDirectory; Nix layout is a test double."""
    def __init__(self):
        self.owner = tempfile.TemporaryDirectory(prefix="host-tool-source-sut-")
        self.root = Path(self.owner.name)
        self.store = self.root / "store"
        self.profiles = self.root / "var/nix/profiles"
        self.state = self.root / "state"
        self.work = self.root / "work"
        for d in (self.store, self.profiles, self.state, self.work):
            d.mkdir(parents=True)
        (self.root / ".source-test-only").write_text("NO_LIVE\n", encoding="utf-8")
        (self.state / "auth-marker").write_bytes(b"synthetic-session-unchanged")
        (self.work / "repo-marker").write_bytes(b"synthetic-work-unchanged")
        (self.root / "base-image").write_bytes(b"B-v0")
        self.selection = self.profiles / "rent-dev"
        self.number = 0
        self.effect_count = 0
        self.attempts: set[str] = set()
        # Ephemeral facts owned by THIS TemporaryDirectory SUT only, NOT a production
        # ledger. An external receipt dict cannot assert an imaginary preimage.
        self._issued: dict[str, tuple[dict, dict, int, str]] = {}
        self._last_attempt: str | None = None
        for path in (STORE0, STORE1):
            d = self.store / Path(path).name
            d.mkdir()
            (d / "tool").write_text(path, encoding="utf-8")

    def close(self):
        self.owner.cleanup()

    def store_for(self, path: str) -> Path:
        if path not in (STORE0, STORE1):
            raise ValueError("foreign Tool not in synthetic closure")
        return self.store / Path(path).name

    def snapshot(self):
        return tuple(p.read_bytes() for p in (
            self.state / "auth-marker", self.work / "repo-marker", self.root / "base-image"))

    def observe(self):
        # Read-only geometry; validate all generations, not just the selected one.
        if (self.profiles.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or list(self.profiles.glob(".rent-dev*"))):
            return "UNKNOWN", None
        generations = list(self.profiles.glob("rent-dev-*-link"))
        for gen in generations:
            if (not gen.is_symlink()
                    or not re.fullmatch(r"rent-dev-[1-9][0-9]*-link", gen.name)
                    or not gen.resolve().is_relative_to(self.store)
                    or not gen.resolve().is_dir()):
                return "UNKNOWN", None
        if not self.selection.is_symlink():
            return ("UNKNOWN", None) if generations or self.selection.exists() else ("ABSENT", None)
        selected = os.readlink(self.selection)
        if not re.fullmatch(r"rent-dev-[1-9][0-9]*-link", selected):
            return "UNKNOWN", None
        generation = self.profiles / selected
        if not generation.is_symlink() or generation not in generations:
            return "UNKNOWN", None
        path = generation.resolve()
        if not path.is_relative_to(self.store) or not path.is_dir():
            return "UNKNOWN", None
        name = path.name
        if name == Path(STORE0).name:
            return "SELECTED", STORE0
        if name == Path(STORE1).name:
            return "SELECTED", STORE1
        return "UNKNOWN", None

    def native_set_fixture(self, path: str, attempt: str, *,
                           desired_revision: str, crash_after_selector=False):
        if (type(desired_revision) is not str
                or not re.fullmatch(r"ci-[0-9a-z-]+", desired_revision)):
            raise ValueError("missing exact synthetic D revision")
        if not (self.root / ".source-test-only").is_file():
            raise ValueError("not a disposable SOURCE fixture")
        if attempt in self.attempts:
            raise ValueError("equivalent attempt cannot be repeated")
        before = self.observe()
        if before[0] == "UNKNOWN":
            raise ValueError("unknown generation geometry")
        self.store_for(path)
        self.number += 1
        generation = f"rent-dev-{self.number}-link"
        (self.profiles / generation).symlink_to(self.store_for(path))
        temp = self.profiles / ".rent-dev-select"
        temp.symlink_to(generation)
        os.replace(temp, self.selection)
        self.effect_count += 1
        self.attempts.add(attempt)
        self._last_attempt = attempt
        if crash_after_selector:
            # A write happened, but no receipt was delivered; a later caller
            # cannot manufacture it from the current geometry and roll back.
            raise RuntimeError("synthetic transport of receipt interrupted")
        receipt = {"attempt": attempt, "preimage": before[1], "selected": path,
                   "effect": "SYNTHETIC_ONLY"}
        self._issued[attempt] = (receipt, copy.deepcopy(receipt), self.number,
                                 desired_revision)
        return receipt

    def rollback_fixture(self, receipt: dict, attempt: str, *, quiet: bool,
                         writer: bool, current_desired: dict):
        if (type(quiet) is not bool or not quiet or type(writer) is not bool
                or not writer or type(receipt) is not dict
                or receipt.get("attempt") != attempt):
            raise ValueError("rollback is not authorized/quiet for the exact attempt")
        issued = self._issued.get(attempt)
        # Object identity, unchanged issued fields, exact current generation
        # and latest actual attempt are all required BEFORE the first selector write.
        # An arbitrary dict (even one copying a real receipt) is never evidence.
        if (issued is None or receipt is not issued[0] or receipt != issued[1]
                or self._last_attempt != attempt or self.number != issued[2]):
            raise ValueError("receipt was not issued by this active SUT attempt")
        # Recovery is a separate effect: even a real same-attempt preimage
        # is stale if the caller's CURRENT D was replaced after the write.
        # This fixture cannot authenticate D; the production owner must do so.
        if (type(current_desired) is not dict
                or current_desired.get("revision") != issued[3]
                or current_desired.get("store_path") != issued[1]["selected"]):
            raise ValueError("rollback would resume a superseded synthetic D")
        if self.observe() != ("SELECTED", issued[1]["selected"]):
            raise ValueError("current selected Tool does not match this attempt")
        preimage = issued[1]["preimage"]
        if preimage is None:
            raise ValueError("cannot blindly roll back first Base-only selection")
        self.store_for(preimage)
        self.native_set_fixture(preimage, attempt + "-rollback",
                                desired_revision=issued[3])
        del self._issued[attempt]  # consumed; cannot be replayed
        return "SYNTHETIC_ROLLBACK_NOT_NEW_D_SUCCESS"


class LifecycleSUT(unittest.TestCase):
    def setUp(self):
        self.host = DisposableHost()
        self.proposal, self.desired, self.observation, self.authority, self.effect = context()

    def tearDown(self):
        self.host.close()

    def gate(self, *, step="TOOL_CHANGE", desired=None, authority=None, previous=None,
             conditions=None):
        f = facts(step)
        if conditions:
            f.update(conditions)
        ostate, store = self.host.observe()
        o = copy.deepcopy(self.observation)
        o.update(state=ostate, store_path=store,
                 fresh=(ostate != "UNKNOWN"), closure_valid=(ostate != "UNKNOWN"))
        synthetic = judge(self.proposal, desired=self.desired if desired is None else desired,
                          observed=o, authority=self.authority if authority is None else authority,
                          previous=self.effect if previous is None else previous)
        stage = evaluate(f)
        self.assertEqual(stage["effect"], "FORBIDDEN")
        self.assertEqual(synthetic["effect"], "FORBIDDEN")
        return synthetic, stage

    def guarded_set(self, path=STORE1, *, attempt="ci-attempt-1",
                    conditions=None, desired=None, previous=None, crash=False):
        guards = self.gate(conditions=conditions, desired=desired, previous=previous)
        if (guards[0]["stage"] != "SYNTHETIC_CHANGE_CANDIDATE"
                or not guards[1]["synthetic_mutation_ready"]):
            return "REFUSED"
        # R1: the executor argument MUST equal this attempt's current D target,
        # not merely be an allowed closure. Do not trust "desired_current=True"
        # or an arbitrary caller-supplied replacement D as a version assertion.
        if (type(path) is not str or path != self.desired["store_path"]
                or (desired is not None and desired != self.desired)):
            return "REFUSED"
        return self.host.native_set_fixture(path, attempt,
                                            desired_revision=self.desired["revision"],
                                            crash_after_selector=crash)

    def test_first_base_only_requires_explicit_d_and_change_guard(self):
        base = self.host.snapshot()
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        no_change = copy.deepcopy(self.authority)
        no_change["change"] = False
        synthetic, stage = self.gate(authority=no_change)
        self.assertEqual(synthetic["stage"], "CHANGE_AUTH_REQUIRED")
        self.assertTrue(stage["synthetic_mutation_ready"])  # independent predicates
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        self.assertEqual(self.guarded_set(conditions={"desired_current": False}), "REFUSED")
        self.assertEqual(self.host.effect_count, 0)
        applied = self.guarded_set()
        self.assertEqual(applied["effect"], "SYNTHETIC_ONLY")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        self.assertEqual(self.host.snapshot(), base)
        self.assertEqual(self.host.effect_count, 1)

    def test_read_is_separate_and_does_not_resolve_previous_unknown(self):
        f = facts("READ")
        f.update(dev_ready=None, desired_current=None, observation_fresh=None,
                 affected_effects_resolved=None, write_unresolved=True)
        self.assertTrue(evaluate(f)["synthetic_read_ready"])
        before = self.host.snapshot()
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        self.assertEqual(self.host.snapshot(), before)
        f["step_authority"] = False
        self.assertFalse(evaluate(f)["synthetic_read_ready"])

    def test_unknown_after_actual_selector_write_does_not_blind_retry(self):
        before = self.host.snapshot()
        with self.assertRaisesRegex(RuntimeError, "receipt interrupted"):
            self.guarded_set(crash=True)
        self.assertEqual(self.host.effect_count, 1)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        # Interrupted receipt transport must not allow a guessed rollback of
        # the same effect; the SUT returned no issued receipt to the caller.
        guessed = {"attempt": "ci-attempt-1", "preimage": STORE0,
                   "selected": STORE1, "effect": "SYNTHETIC_ONLY"}
        with self.assertRaises(ValueError):
            self.host.rollback_fixture(guessed, "ci-attempt-1", quiet=True, writer=True)
        self.assertEqual(self.host.effect_count, 1)
        # Old effect is UNKNOWN even though the selector looks new; no auto change/success.
        e = copy.deepcopy(self.effect)
        e["state"] = "UNKNOWN"
        s, _stage = self.gate(previous=e)
        self.assertEqual(s["stage"], "E_UNKNOWN")
        self.assertEqual(self.guarded_set(previous=e, attempt="ci-attempt-2"), "REFUSED")
        self.assertEqual(self.host.effect_count, 1)
        self.assertEqual(self.host.snapshot(), before)
        # Separately confirmed result may propose RECORD ONLY, never re-select the Tool.
        f = facts("RECORD")
        self.assertTrue(evaluate(f)["synthetic_mutation_ready"])
        self.assertEqual(self.host.effect_count, 1)

    def test_current_d_revision_changed_or_quiet_lost_blocks_without_write(self):
        for change in (
            {"desired_current": False}, {"observation_fresh": None},
            {"quiet_held": False}, {"one_writer": None},
            {"recovery_available": False}, {"write_unresolved": True},
        ):
            before = self.host.snapshot()
            self.assertEqual(self.guarded_set(conditions=change), "REFUSED")
            self.assertEqual(self.host.effect_count, 0)
            self.assertEqual(self.host.snapshot(), before)
        foreign = copy.deepcopy(self.desired)
        foreign["revision"] = "ci-stale"
        foreign["proposed_q"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            self.guarded_set(desired=foreign)
        self.assertEqual(self.host.observe(), ("ABSENT", None))

    def test_state_unknown_or_foreign_selector_stops_even_synthetic_change(self):
        self.host.selection.symlink_to("/tmp/foreign")
        self.assertEqual(self.host.observe(), ("UNKNOWN", None))
        s, _ = self.gate()
        self.assertEqual(s["stage"], "O_UNKNOWN_OR_STALE")
        self.assertEqual(self.guarded_set(), "REFUSED")
        self.assertEqual(self.host.effect_count, 0)
        self.host.selection.unlink()
        self.host.profiles.chmod(0o777)
        self.assertEqual(self.host.observe(), ("UNKNOWN", None))
        self.host.profiles.chmod(0o755)

    def test_r1_wrong_allowlisted_tool_or_stale_supplied_d_refused_without_writes(self):
        # R's exact counterexample: desired T1, but allowed T0 was directly
        # supplied as the selector argument. Both closures exist in the test store.
        original = self.host.snapshot()
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        self.assertEqual(self.desired["store_path"], STORE1)
        for bad_path in (STORE0, "/nix/store/" + "c" * 32 + "-other"):
            self.assertEqual(
                self.guarded_set(path=bad_path, attempt="ci-wrong-tool"),
                "REFUSED",
            )
            self.assertEqual(self.host.effect_count, 0)
            self.assertEqual(self.host.number, 0)
            self.assertFalse(self.host.attempts)
            self.assertEqual(self.host.observe(), ("ABSENT", None))
            self.assertEqual(self.host.snapshot(), original)

        # Even a correctly shaped synthetic alternative D is not the currently
        # bound D for this SUT. The caller cannot swap D and choose an old q.
        old_revision = copy.deepcopy(self.desired)
        old_revision["revision"] = "ci-r2"
        self.assertEqual(self.guarded_set(desired=old_revision), "REFUSED")
        old_tool = copy.deepcopy(self.desired)
        old_tool["store_path"] = STORE0
        self.assertEqual(self.guarded_set(path=STORE0, desired=old_tool), "REFUSED")
        self.assertEqual(self.host.effect_count, 0)
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        self.assertEqual(self.host.snapshot(), original)

        # The same allowed closure becomes eligible only after the SUT's own
        # current synthetic D explicitly selects it.
        self.desired["store_path"] = STORE0
        emitted = self.guarded_set(path=STORE0, attempt="ci-explicit-d-t0")
        self.assertIsInstance(emitted, dict)
        self.assertEqual(emitted["selected"], STORE0)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.assertEqual(self.host.effect_count, 1)
        self.assertEqual(self.host.snapshot(), original)

    def test_r2_forged_receipt_and_old_attempt_preimage_never_roll_back(self):
        self.desired["store_path"] = STORE0
        first = self.guarded_set(path=STORE0, attempt="ci-preimage")
        self.assertIsInstance(first, dict)
        self.desired["store_path"] = STORE1
        actual = self.guarded_set(path=STORE1, attempt="ci-rotate")
        self.assertEqual(actual["preimage"], STORE0)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        old_state = self.host.snapshot()
        old_count = self.host.effect_count
        old_generation = self.host.number

        fake_never_issued = {
            "attempt": "never-ran", "selected": STORE1,
            "preimage": STORE0, "effect": "SYNTHETIC_ONLY",
        }
        fake_same_fields = copy.deepcopy(actual)
        fake_altered_preimage = copy.deepcopy(actual)
        fake_altered_preimage["preimage"] = STORE1
        for forged, claimed_attempt in (
            (fake_never_issued, "never-ran"),
            (fake_same_fields, "ci-rotate"),
            (fake_altered_preimage, "ci-rotate"),
        ):
            with self.subTest(forged=claimed_attempt, preimage=forged["preimage"]):
                with self.assertRaises(ValueError):
                    self.host.rollback_fixture(
                        forged, claimed_attempt, quiet=True, writer=True
                    )
                self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
                self.assertEqual(self.host.effect_count, old_count)
                self.assertEqual(self.host.number, old_generation)
                self.assertEqual(self.host.snapshot(), old_state)

        # A mutation to the actual object must also invalidate the frozen SUT
        # issued record; restoring it is not an arbitrary new admission.
        actual["preimage"] = STORE1
        with self.assertRaises(ValueError):
            self.host.rollback_fixture(actual, "ci-rotate", quiet=True, writer=True)
        self.assertEqual(self.host.effect_count, old_count)
        actual["preimage"] = STORE0

        self.assertEqual(
            self.host.rollback_fixture(actual, "ci-rotate", quiet=True, writer=True),
            "SYNTHETIC_ROLLBACK_NOT_NEW_D_SUCCESS",
        )
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.desired["store_path"] = STORE1
        self.guarded_set(path=STORE1, attempt="ci-newer-selection")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        count_after_new = self.host.effect_count
        # A previously issued/consumed receipt cannot be replayed even if a
        # later attempt happens to select the very same store path.
        with self.assertRaises(ValueError):
            self.host.rollback_fixture(actual, "ci-rotate", quiet=True, writer=True)
        self.assertEqual(self.host.effect_count, count_after_new)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        self.assertEqual(self.host.snapshot(), old_state)

    def test_rollback_only_same_attempt_and_same_preimage(self):
        # First T0 is the original preimage of an actual synthetic T1 selection.
        self.desired["store_path"] = STORE0
        first = self.guarded_set(path=STORE0, attempt="ci-0")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.desired["store_path"] = STORE1
        second = self.guarded_set(path=STORE1, attempt="ci-1")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        for options in (
            {"attempt": "another", "quiet": True, "writer": True},
            {"attempt": "ci-1", "quiet": False, "writer": True},
            {"attempt": "ci-1", "quiet": True, "writer": False},
        ):
            with self.assertRaises(ValueError):
                self.host.rollback_fixture(second, **options)
            self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        before = self.host.snapshot()
        self.assertEqual(self.host.rollback_fixture(second, "ci-1", quiet=True, writer=True),
                         "SYNTHETIC_ROLLBACK_NOT_NEW_D_SUCCESS")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.assertEqual(self.host.snapshot(), before)
        self.assertEqual(self.host.effect_count, 3)
        self.assertEqual(first["preimage"], None)
        with self.assertRaises(ValueError):
            self.host.rollback_fixture(first, "ci-0", quiet=True, writer=True)

    def test_source_change_is_not_target_noop_or_success(self):
        before = self.host.snapshot()
        self.assertEqual(evaluate(facts("SOURCE_FIX"))["stage"], "SYNTHETIC_STEP_READY")
        self.assertEqual(self.host.observe(), ("ABSENT", None))
        self.assertEqual(self.host.snapshot(), before)
        s, _ = self.gate()
        self.assertEqual(s["target_noop"], "UNPROVEN")
        self.assertEqual(s["effect"], "FORBIDDEN")

    def test_same_target_tool_delta_does_not_mutate_base_or_work(self):
        before = self.host.snapshot()
        self.desired["store_path"] = STORE0
        self.guarded_set(path=STORE0, attempt="t0")
        self.desired["store_path"] = STORE1
        self.guarded_set(path=STORE1, attempt="t1")
        self.assertEqual(self.host.snapshot(), before)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        self.assertEqual(self.host.effect_count, 2)


if __name__ == "__main__":
    unittest.main()
