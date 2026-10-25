"""Synthetic plan-admission tests only; no provider, network or apply."""
import copy
import unittest

from check_initial_plan import MANAGED, TOKEN, check


def fixture():
    return {
        "format_version": "1.2",
        "resource_changes": [
            {"address": address, "mode": "managed", "change": {"actions": ["create"]}}
            for address in sorted(MANAGED)
        ] + [{"address": TOKEN, "mode": "data", "change": {"actions": ["read"]}}],
        "output_changes": {
            "public_binding": {"after_sensitive": False},
            "connector_token": {"after_sensitive": True},
        },
    }


class Admission(unittest.TestCase):
    def test_initial_create(self):
        check(fixture())

    def test_refuses_destructive_or_existing_state_operations(self):
        for actions in (["delete"], ["update"], ["delete", "create"], ["no-op"]):
            with self.subTest(actions=actions), self.assertRaises(ValueError):
                plan = fixture()
                plan["resource_changes"][0]["change"]["actions"] = actions
                check(plan)

    def test_refuses_rent_or_extra_resource(self):
        plan = fixture()
        plan["resource_changes"].append({"address": "cloudflare_dns_record.rent", "mode": "managed", "change": {"actions": ["update"]}})
        with self.assertRaises(ValueError):
            check(plan)

    def test_refuses_missing_duplicate_or_wrong_mode(self):
        original = fixture()
        for mutate in (
            lambda p: p["resource_changes"].pop(0),
            lambda p: p["resource_changes"].append(copy.deepcopy(p["resource_changes"][0])),
            lambda p: p["resource_changes"][0].update(mode="data"),
        ):
            plan = copy.deepcopy(original)
            mutate(plan)
            with self.assertRaises(ValueError):
                check(plan)

    def test_refuses_token_disclosure_and_incomplete_plan(self):
        for mutate in (
            lambda p: p["output_changes"]["connector_token"].update(after_sensitive=False),
            lambda p: p["output_changes"].update(other_secret={}),
            lambda p: p.update(complete=False),
            lambda p: p.update(errored=True),
            lambda p: p.update(deferred_changes=[{}]),
        ):
            plan = fixture()
            mutate(plan)
            with self.assertRaises(ValueError):
                check(plan)


if __name__ == "__main__":
    unittest.main()
