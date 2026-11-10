# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_rule_explainer.py

<Purpose>
  Test the machine-readable artifact rule explanations in
  ``in_toto.rule_explainer`` and their integration in ``in_toto.verifylib``.
"""

import json
import unittest

import securesystemslib.exceptions

from in_toto.exceptions import RuleVerificationError
from in_toto.models.link import Link
from in_toto.rule_explainer import (
    MATCH_DIGEST_MISMATCH,
    MATCH_MATCHED,
    MATCH_MISSING_DESTINATION,
    PROVENANCE_INSPECTION,
    PROVENANCE_SIGNATURE_VERIFIED,
    PROVENANCE_UNVERIFIED,
    RULE_FAILED,
    RuleExplainer,
    RuleVerificationReport,
)
from in_toto.verifylib import (
    verify_allow_rule,
    verify_create_rule,
    verify_delete_rule,
    verify_disallow_rule,
    verify_item_rules,
    verify_match_rule,
    verify_modify_rule,
    verify_require_rule,
)

H1 = {"sha256": "1" * 64}
H2 = {"sha256": "2" * 64}
H3 = {"sha256": "3" * 64}


class RuleExplainerTest(unittest.TestCase):
    """Shared fixtures for explainer tests."""

    def setUp(self):
        # "item": foo unchanged, bar modified, baz created, old deleted.
        self.links = {
            "item": Link(
                name="item",
                materials={
                    "foo": H1,
                    "bar": H1,
                    "old": H1,
                    "sub/foo": H1,
                },
                products={
                    "foo": H1,
                    "bar": H2,
                    "baz": H3,
                    "sub/foo": H1,
                },
            ),
            # Destination link for MATCH rules.
            "other": Link(
                name="other",
                materials={"foo": H1, "bar": H3},
                products={"relocated/foo": H1},
            ),
        }
        self.provenance = {
            "item": PROVENANCE_SIGNATURE_VERIFIED,
            "other": PROVENANCE_SIGNATURE_VERIFIED,
        }

    def _explain(self, rules, source_type="products", **kwargs):
        report = RuleVerificationReport()
        explainer = RuleExplainer(
            self.links, link_provenance=self.provenance, **kwargs
        )
        explainer.explain_item_rules(
            report, "item", source_type, rules
        )
        return report.get_item("item", source_type)

    def test_json_serializable(self):
        """The report round-trips through JSON without losing information."""
        rules = [
            ["MODIFY", "bar"],
            ["ALLOW", "*"],
        ]
        report = RuleVerificationReport()
        RuleExplainer(self.links).explain_item_rules(
            report, "item", "products", rules
        )
        encoded = report.to_json()
        decoded = json.loads(encoded)
        self.assertEqual(
            decoded["items"][0]["item_name"], "item"
        )
        self.assertEqual(
            decoded["items"][0]["rule_explanations"][0]["rule_type"],
            "modify",
        )

    def test_queue_snapshots_are_complete_and_ordered(self):
        """Queue before/after always carry every remaining path, sorted."""
        rules = [
            ["MODIFY", "bar"],
            ["CREATE", "baz"],
            ["DISALLOW", "*"],
        ]
        report = RuleVerificationReport()
        with self.assertRaises(RuleVerificationError):
            RuleExplainer(self.links).explain_item_rules(
                report, "item", "products", rules
            )
        item = report.get_item("item", "products")
        modify, create, disallow = item.rule_explanations

        self.assertEqual(
            modify.queue_before,
            ["bar", "baz", "foo", "sub/foo"],
        )
        self.assertEqual(modify.queue_after, ["baz", "foo", "sub/foo"])
        self.assertEqual(modify.consumed, ["bar"])
        self.assertEqual(create.queue_before, ["baz", "foo", "sub/foo"])
        self.assertEqual(create.queue_after, ["foo", "sub/foo"])
        # Unconsumed artifacts reach the terminal DISALLOW and fail.
        self.assertEqual(disallow.status, RULE_FAILED)
        self.assertEqual(
            disallow.queue_after, ["foo", "sub/foo"]
        )

    def test_create_delete_modify_judgments(self):
        """Generic rules record consumed vs skipped with a reason."""
        rules = [
            ["CREATE", "*"],
            ["DELETE", "*"],
            ["MODIFY", "*"],
            ["ALLOW", "*"],
        ]
        item = self._explain(rules, source_type="products")
        create, _delete, modify, allow = item.rule_explanations

        create_paths = {j.path: j for j in create.judgments}
        self.assertEqual(create_paths["baz"].outcome, "consumed")
        # foo is a material too, hence not a creation.
        self.assertEqual(
            create_paths["foo"].outcome, "skipped"
        )
        self.assertEqual(create_paths["foo"].reason, "in-materials")

        modify_paths = {j.path: j for j in modify.judgments}
        self.assertEqual(modify_paths["bar"].outcome, "consumed")
        self.assertEqual(
            modify_paths["foo"].outcome, "skipped"
        )
        self.assertEqual(modify_paths["foo"].reason, "same-digest")
        self.assertEqual(
            modify_paths["bar"].hashes["materials"], H1
        )
        self.assertEqual(
            modify_paths["bar"].hashes["products"], H2
        )

        self.assertTrue(
            all(j.outcome == "consumed" for j in allow.judgments)
        )

    def test_delete_on_materials_queue(self):
        """DELETE consumes a material that does not appear in products."""
        rules = [["DELETE", "old"], ["ALLOW", "*"]]
        item = self._explain(rules, source_type="materials")
        delete = item.rule_explanations[0]
        self.assertEqual(delete.consumed, ["old"])
        judgment = next(
            j for j in delete.judgments if j.path == "old"
        )
        self.assertEqual(judgment.outcome, "consumed")

    def test_match_matched_missing_and_mismatch(self):
        """MATCH distinguishes the three destination outcomes."""
        rules = [
            # foo exists in other.materials with the same digest -> matched.
            ["MATCH", "foo", "WITH", "MATERIALS", "FROM", "other"],
            # bar exists in other.materials but digest differs -> mismatch.
            ["MATCH", "bar", "WITH", "MATERIALS", "FROM", "other"],
            # baz has no counterpart in other.materials -> missing.
            ["MATCH", "baz", "WITH", "MATERIALS", "FROM", "other"],
            ["ALLOW", "*"],
        ]
        item = self._explain(rules)
        match_foo, match_bar, match_baz, _allow = item.rule_explanations

        foo = match_foo.matches[0]
        self.assertEqual(foo.outcome, MATCH_MATCHED)
        self.assertEqual(foo.source_path, "foo")
        self.assertEqual(foo.destination_path, "foo")
        self.assertEqual(foo.destination_name, "other")
        self.assertEqual(foo.destination_type, "materials")
        self.assertEqual(foo.hash_algorithms, ["sha256"])
        self.assertEqual(foo.source_hashes, H1)
        self.assertEqual(foo.destination_hashes, H1)
        self.assertEqual(match_foo.consumed, ["foo"])
        self.assertTrue(match_foo.destination_link["trusted"])

        bar = match_bar.matches[0]
        self.assertEqual(bar.outcome, MATCH_DIGEST_MISMATCH)
        self.assertEqual(bar.source_hashes, H2)
        self.assertEqual(bar.destination_hashes, H3)
        self.assertEqual(match_bar.consumed, [])

        baz = match_baz.matches[0]
        self.assertEqual(baz.outcome, MATCH_MISSING_DESTINATION)
        self.assertIsNone(baz.destination_hashes)
        self.assertEqual(match_baz.consumed, [])

    def test_match_prefix_transformation(self):
        """Source and destination prefixes are recorded on the explanation."""
        rules = [
            [
                "MATCH",
                "foo",
                "IN",
                "sub",
                "WITH",
                "PRODUCTS",
                "IN",
                "relocated",
                "FROM",
                "other",
            ],
            ["ALLOW", "*"],
        ]
        item = self._explain(rules)
        match = item.rule_explanations[0]
        entry = match.matches[0]
        self.assertEqual(entry.source_path, "sub/foo")
        self.assertEqual(entry.destination_path, "relocated/foo")
        self.assertEqual(entry.source_prefix, "sub")
        self.assertEqual(entry.destination_prefix, "relocated")
        self.assertEqual(entry.outcome, MATCH_MATCHED)
        self.assertEqual(match.consumed, ["sub/foo"])

    def test_match_missing_destination_link(self):
        """A missing destination link yields missing outcomes, no trust."""
        rules = [
            ["MATCH", "foo", "WITH", "MATERIALS", "FROM", "ghost"],
            ["ALLOW", "*"],
        ]
        item = self._explain(rules)
        match = item.rule_explanations[0]
        self.assertIsNone(match.destination_link)
        self.assertEqual(
            match.matches[0].outcome, MATCH_MISSING_DESTINATION
        )
        self.assertEqual(match.consumed, [])

    def test_disallow_failure_keeps_partial_report(self):
        """Results up to and including the failing DISALLOW are retained."""
        rules = [
            ["MODIFY", "bar"],
            ["DISALLOW", "foo"],
        ]
        report = RuleVerificationReport()
        explainer = RuleExplainer(self.links)
        with self.assertRaises(RuleVerificationError):
            explainer.explain_item_rules(
                report, "item", "products", rules
            )
        item = report.get_item("item", "products")
        self.assertTrue(item.failed)
        self.assertIn("DISALLOW", item.failure_message)
        self.assertEqual(len(item.rule_explanations), 2)
        failing = item.rule_explanations[-1]
        self.assertEqual(failing.status, RULE_FAILED)
        self.assertEqual(
            [j.path for j in failing.judgments], ["foo"]
        )
        # Queue snapshot at the failure location is still available.
        self.assertEqual(failing.queue_after, ["baz", "foo", "sub/foo"])

    def test_require_failure_records_queue(self):
        """A failing REQUIRE keeps its queue snapshot and message."""
        rules = [["REQUIRE", "does-not-exist"]]
        report = RuleVerificationReport()
        explainer = RuleExplainer(self.links)
        with self.assertRaises(RuleVerificationError):
            explainer.explain_item_rules(
                report, "item", "products", rules
            )
        item = report.get_item("item", "products")
        failing = item.rule_explanations[-1]
        self.assertEqual(failing.status, RULE_FAILED)
        self.assertIn("does-not-exist", failing.error)
        self.assertEqual(
            failing.queue_after, ["bar", "baz", "foo", "sub/foo"]
        )

    def test_artifact_filter_limits_evidence_not_behavior(self):
        """Filtered-out rules still run; only detailed evidence is omitted."""
        rules = [
            ["MODIFY", "bar"],
            ["CREATE", "baz"],
            ["DISALLOW", "*"],
        ]
        # Only ask about "bar". CREATE still consumes "baz"; the unconsumed
        # "foo" and "sub/foo" still fail the terminal DISALLOW.
        report = RuleVerificationReport()
        with self.assertRaises(RuleVerificationError):
            RuleExplainer(
                self.links, artifact_filter={"bar"}
            ).explain_item_rules(report, "item", "products", rules)
        item = report.get_item("item", "products")
        modify, create, disallow = item.rule_explanations

        self.assertEqual(
            [j.path for j in modify.judgments], ["bar"]
        )
        # baz was consumed by CREATE despite having no emitted judgment.
        self.assertEqual(create.consumed, ["baz"])
        self.assertEqual(create.judgments, [])
        # Queue snapshots remain complete.
        self.assertEqual(
            create.queue_before, ["baz", "foo", "sub/foo"]
        )
        self.assertEqual(disallow.judgments, [])
        self.assertEqual(disallow.queue_before, ["foo", "sub/foo"])

    def test_unverified_link_is_never_trusted(self):
        """Links without provenance default to unverified and untrusted."""
        report = RuleVerificationReport()
        RuleExplainer(self.links).explain_item_rules(
            report,
            "item",
            "products",
            [["ALLOW", "*"]],
        )
        item = report.get_item("item", "products")
        self.assertEqual(item.link_provenance, PROVENANCE_UNVERIFIED)
        self.assertFalse(item.link_trusted)

    def test_inspection_provenance_label(self):
        """Inspection links are labeled as locally generated."""
        report = RuleVerificationReport()
        RuleExplainer(
            self.links,
            link_provenance={"item": PROVENANCE_INSPECTION},
        ).explain_item_rules(
            report, "item", "products", [["ALLOW", "*"]]
        )
        item = report.get_item("item", "products")
        self.assertEqual(item.link_provenance, PROVENANCE_INSPECTION)
        self.assertFalse(item.link_trusted)

    def test_invalid_provenance_rejected(self):
        with self.assertRaises(ValueError):
            RuleExplainer(self.links, link_provenance={"item": "bogus"})

    def test_invalid_source_type(self):
        report = RuleVerificationReport()
        with self.assertRaises(
            securesystemslib.exceptions.FormatError
        ):
            RuleExplainer(self.links).explain_item_rules(
                report, "item", "artifacts", []
            )

    def test_consumption_matches_reference_implementation(self):
        """The explainer's consumed sets match verifylib's rule functions."""
        # Build an arbitrary queue and exercise every generic rule type.
        queue = set(self.links["item"].products.keys())
        materials = set(self.links["item"].materials.keys())
        products = set(self.links["item"].products.keys())

        cases = [
            (
                ["CREATE", "*"],
                verify_create_rule(
                    "*", set(queue), materials, products
                ),
                "create",
            ),
            (
                ["DELETE", "*"],
                verify_delete_rule(
                    "*", set(queue), materials, products
                ),
                "delete",
            ),
            (
                ["MODIFY", "*"],
                verify_modify_rule(
                    "*",
                    set(queue),
                    self.links["item"].materials,
                    self.links["item"].products,
                ),
                "modify",
            ),
            (
                ["ALLOW", "*"],
                verify_allow_rule("*", set(queue)),
                "allow",
            ),
        ]
        for rule, expected, label in cases:
            item = self._explain([rule])
            self.assertEqual(
                set(item.rule_explanations[0].consumed),
                expected,
                label,
            )

    def test_match_consumption_matches_reference_implementation(self):
        rule_data_rule = [
            "MATCH",
            "foo",
            "WITH",
            "MATERIALS",
            "FROM",
            "other",
        ]
        from in_toto.rulelib import unpack_rule

        queue = set(self.links["item"].products.keys())
        expected = verify_match_rule(
            unpack_rule(rule_data_rule),
            set(queue),
            self.links["item"].products,
            self.links,
        )
        item = self._explain([rule_data_rule])
        self.assertEqual(
            set(item.rule_explanations[0].consumed), expected
        )

    def test_reference_disallow_and_require_still_raise(self):
        """The legacy rule functions raise the same exception type."""
        from in_toto import verifylib

        # Populate the global trace used when building error messages.
        verifylib.verify_item_rules(
            "item", "products", [["ALLOW", "*"]], self.links
        )
        with self.assertRaises(RuleVerificationError):
            verify_disallow_rule(
                "*", set(self.links["item"].products.keys())
            )
        with self.assertRaises(RuleVerificationError):
            verify_require_rule(
                "missing", set(self.links["item"].products.keys())
            )


class VerifyItemRulesIntegrationTest(unittest.TestCase):
    """The optional report argument integrates with verifylib's entry point."""

    def setUp(self):
        self.links = {
            "item": Link(
                name="item",
                materials={"foo": H1},
                products={"bar": H2},
            )
        }

    def test_report_populated_via_verify_item_rules(self):
        report = RuleVerificationReport()
        verify_item_rules(
            "item",
            "products",
            [["CREATE", "bar"], ["DISALLOW", "*"]],
            self.links,
            report=report,
            link_provenance={
                "item": PROVENANCE_SIGNATURE_VERIFIED
            },
        )
        item = report.get_item("item", "products")
        self.assertIsNotNone(item)
        self.assertTrue(item.link_trusted)
        self.assertEqual(len(item.rule_explanations), 2)

    def test_legacy_path_without_report_unchanged(self):
        """No report -> legacy global-trace code path, no error."""
        verify_item_rules(
            "item",
            "products",
            [["CREATE", "bar"], ["DISALLOW", "*"]],
            self.links,
        )

    def test_failure_via_verify_item_rules_keeps_report(self):
        report = RuleVerificationReport()
        with self.assertRaises(RuleVerificationError):
            verify_item_rules(
                "item",
                "products",
                [["DISALLOW", "*"]],
                self.links,
                report=report,
            )
        item = report.get_item("item", "products")
        self.assertTrue(item.failed)
        self.assertEqual(item.rule_explanations[-1].status, RULE_FAILED)

    def test_filter_threaded_through_verify_item_rules(self):
        report = RuleVerificationReport()
        verify_item_rules(
            "item",
            "products",
            [["ALLOW", "*"]],
            self.links,
            report=report,
            artifact_filter={"bar"},
        )
        item = report.get_item("item", "products")
        self.assertEqual(
            [j.path for j in item.rule_explanations[0].judgments],
            ["bar"],
        )


if __name__ == "__main__":
    unittest.main()
