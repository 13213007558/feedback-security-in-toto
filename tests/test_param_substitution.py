# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_param_substitution.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  May 15, 2018

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test the parameter substitution functions within verifylib. These tests were
  placed in a separate module to ease refactoring in case the substitution
  layer is to be removed.

"""

import copy
import os
import unittest

from securesystemslib.exceptions import FormatError

import in_toto.exceptions
import in_toto.settings
from in_toto.exceptions import ParameterSubstitutionError
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT
from in_toto.models.metadata import Envelope, Metablock
from in_toto.verifylib import in_toto_verify, substitute_parameters
from tests.common import SignerStore, TmpDirMixin


class TestSubstituteArtifacts(unittest.TestCase):
    """Test parameter substitution on artifact rules."""

    def setUp(self):
        self.layout = Layout.read(
            {
                "_type": "layout",
                "inspect": [
                    {
                        "name": "do-the-thing",
                        "expected_materials": [
                            [
                                "MATCH",
                                "{SOURCE_THING}",
                                "WITH",
                                "MATERIALS",
                                "FROM",
                                "{SOURCE_STEP}",
                            ]
                        ],
                        "expected_products": [["CREATE", "{NEW_THING}"]],
                    }
                ],
                "steps": [
                    {
                        "name": "artifacts",
                        "expected_command": [],
                        "expected_materials": [
                            [
                                "MATCH",
                                "{SOURCE_THING}",
                                "WITH",
                                "MATERIALS",
                                "FROM",
                                "{SOURCE_STEP}",
                            ]
                        ],
                        "expected_products": [["CREATE", "{NEW_THING}"]],
                    }
                ],
            }
        )

    def test_substitute(self):
        """Do a simple substitution on the expected_command field"""
        substitute_parameters(
            self.layout,
            {
                "SOURCE_THING": "vim",
                "SOURCE_STEP": "source_step",
                "NEW_THING": "new_thing",
            },
        )
        self.assertEqual(self.layout.steps[0].expected_materials[0][1], "vim")
        self.assertEqual(
            self.layout.steps[0].expected_materials[0][5], "source_step"
        )
        self.assertEqual(
            self.layout.steps[0].expected_products[0][1], "new_thing"
        )
        self.assertEqual(self.layout.inspect[0].expected_materials[0][1], "vim")
        self.assertEqual(
            self.layout.inspect[0].expected_materials[0][5], "source_step"
        )
        self.assertEqual(
            self.layout.inspect[0].expected_products[0][1], "new_thing"
        )

    def test_substitute_no_var(self):
        """Raise an error if the parameter is not filled-in"""
        with self.assertRaises(KeyError):
            substitute_parameters(self.layout, {})

    def test_invalid_format(self):
        for bad_param_dict in [
            False,  # must be dict
            {False: "foo"},  # name must be string
            {"~!#@": "foo"},  # name must not have disallowed characters
            {"GOOD_NAME": False},  # value must be string
        ]:
            with self.assertRaises(FormatError):
                substitute_parameters(self.layout, bad_param_dict)


class TestSubstituteRunField(unittest.TestCase):
    """Test substitution on the run field of the layout"""

    def setUp(self):
        """
        Create layout with dummy inspection
        """

        # Create layout with one inspection
        self.layout = Layout.read(
            {
                "_type": "layout",
                "steps": [],
                "inspect": [
                    {
                        "name": "run-command",
                        "run": ["{COMMAND}"],
                    }
                ],
            }
        )

    def test_substitute(self):
        """Check that the substitution is performed on the run field."""
        substitute_parameters(self.layout, {"COMMAND": "touch"})
        self.assertEqual(self.layout.inspect[0].run[0], "touch")

    def test_inspection_fail_with_non_zero_retval(self):
        """Check that the substitution raises TypeError if the key is missing"""

        with self.assertRaises(KeyError):
            substitute_parameters(self.layout, {})


class TestSubstituteExpectedCommand(unittest.TestCase):
    """Test verifylib.verify_command_alignment(command, expected_command)"""

    def setUp(self):
        # Create layout with one inspection
        self.layout = Layout.read(
            {
                "_type": "layout",
                "inspect": [],
                "steps": [
                    {
                        "name": "run-command",
                        "expected_command": ["{EDITOR}"],
                    }
                ],
            }
        )

    def test_substitute(self):
        """Do a simple substitution on the expected_command field"""
        substitute_parameters(self.layout, {"EDITOR": "vim"})
        self.assertEqual(self.layout.steps[0].expected_command[0], "vim")

    def test_substitute_no_var(self):
        """Raise an error if the parameter is not filled-in"""

        with self.assertRaises(KeyError):
            substitute_parameters(self.layout, {"NOEDITOR": "vim"})


class TestSubstituteOnVerify(unittest.TestCase):
    """Test verifylib.verify_command_alignment(command, expected_command)"""

    @classmethod
    def setUpClass(cls):
        # Create layout with one inspection
        cls.layout = Layout.read(
            {
                "_type": "layout",
                "inspect": [],
                "steps": [
                    {
                        "name": "run-command",
                        "expected_command": ["{EDITOR}"],
                    }
                ],
            }
        )

        # load alice's key
        cls.alice = SignerStore.rsa
        cls.alice_pub_dict = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}

    def test_substitute(self):
        """Do a simple substitution on the expected_command field"""
        signed_layout = Metablock(signed=self.layout)
        signed_layout.create_signature(self.alice)

        # we will catch a LinkNotFound error because we don't have (and don't need)
        # the metadata.
        with self.assertRaises(in_toto.exceptions.LinkNotFoundError):
            in_toto_verify(
                signed_layout,
                self.alice_pub_dict,
                substitution_parameters={"EDITOR": "vim"},
            )

        self.assertEqual(self.layout.steps[0].expected_command[0], "vim")

    def test_substitute_for_envelope(self):
        """Do a simple substitution on the expected_command field for DSSE
        envelope."""
        signed_layout = Envelope.from_signable(self.layout)
        signed_layout.create_signature(self.alice)

        # we will catch a LinkNotFound error because we don't have (and don't need)
        # the metadata.
        with self.assertRaises(in_toto.exceptions.LinkNotFoundError):
            in_toto_verify(
                signed_layout,
                self.alice_pub_dict,
                substitution_parameters={"EDITOR": "vim"},
            )

        self.assertEqual(self.layout.steps[0].expected_command[0], "vim")


class TestStrictSubstituteAllFields(unittest.TestCase):
    """Strict mode substitutes the same four field families as legacy mode."""

    LAYOUT_DATA = {
        "_type": "layout",
        "steps": [
            {
                "name": "step",
                "expected_command": ["run", "{COMMAND}"],
                "expected_materials": [
                    [
                        "MATCH",
                        "{SOURCE}",
                        "WITH",
                        "MATERIALS",
                        "FROM",
                        "{SRC_STEP}",
                    ]
                ],
                "expected_products": [["CREATE", "{PRODUCT}"]],
            }
        ],
        "inspect": [
            {
                "name": "inspection",
                "run": ["verify", "{COMMAND}"],
                "expected_materials": [["DISALLOW", "{SOURCE}"]],
                "expected_products": [["REQUIRE", "{PRODUCT}"]],
            }
        ],
    }

    PARAMS = {
        "COMMAND": "build",
        "SOURCE": "src/app.c",
        "SRC_STEP": "write-code",
        "PRODUCT": "out/app.o",
    }

    def setUp(self):
        self.layout = Layout.read(copy.deepcopy(self.LAYOUT_DATA))

    def test_strict_covers_materials_products_command_and_run(self):
        substitute_parameters(self.layout, self.PARAMS, strict=True)

        step = self.layout.steps[0]
        self.assertEqual(step.expected_command, ["run", "build"])
        self.assertEqual(
            step.expected_materials[0],
            ["MATCH", "src/app.c", "WITH", "MATERIALS", "FROM", "write-code"],
        )
        self.assertEqual(step.expected_products[0], ["CREATE", "out/app.o"])

        inspection = self.layout.inspect[0]
        self.assertEqual(inspection.run, ["verify", "build"])
        self.assertEqual(
            inspection.expected_materials[0], ["DISALLOW", "src/app.c"]
        )
        self.assertEqual(
            inspection.expected_products[0], ["REQUIRE", "out/app.o"]
        )

    def test_strict_escaped_braces_are_literal(self):
        layout = Layout.read(
            {
                "_type": "layout",
                "inspect": [
                    {"name": "i", "run": ["{{not-a-placeholder}} {X}"]}
                ],
                "steps": [],
            }
        )
        substitute_parameters(layout, {"X": "v"}, strict=True)
        self.assertEqual(layout.inspect[0].run[0], "{not-a-placeholder} v")


class TestStrictRejectsUnsafeSyntax(unittest.TestCase):
    """Strict mode rejects anything that is not a simple {name} placeholder."""

    PARAMS = {"X": "value", "Y": "other"}

    def _layout_with_template(self, template):
        return Layout.read(
            {
                "_type": "layout",
                "steps": [{"name": "s", "expected_command": [template]}],
                "inspect": [],
            }
        )

    def test_reject_attribute_index_conversion_and_format_spec(self):
        templates = [
            "{X.attr}",  # attribute access
            "{X[0]}",  # subscript / index
            "{X!r}",  # conversion flag
            "{X:>10}",  # format specification
            "{}",  # empty placeholder
            "{X}{Z}",  # second placeholder references a missing parameter
            "prefix {MISSING} suffix",  # missing parameter
            "{X",  # unmatched opening brace
            "X}",  # unescaped closing brace
        ]
        for template in templates:
            with self.subTest(template=template):
                layout = self._layout_with_template(template)
                with self.assertRaises(ParameterSubstitutionError):
                    substitute_parameters(layout, self.PARAMS, strict=True)

    def test_strict_missing_parameter_raises_dedicated_error(self):
        layout = self._layout_with_template("{UNKNOWN}")
        with self.assertRaises(ParameterSubstitutionError):
            substitute_parameters(layout, self.PARAMS, strict=True)

    def test_malformed_parameter_dict_still_raises_format_error(self):
        layout = self._layout_with_template("{X}")
        for bad_param_dict in [
            False,
            {False: "foo"},
            {"~!#@": "foo"},
            {"GOOD_NAME": False},
        ]:
            with self.subTest(bad=bad_param_dict):
                with self.assertRaises(FormatError):
                    substitute_parameters(layout, bad_param_dict, strict=True)


class TestStrictAtomicity(unittest.TestCase):
    """A failure anywhere leaves the entire layout unsubstituted."""

    def setUp(self):
        self.layout = Layout.read(
            {
                "_type": "layout",
                "steps": [
                    {
                        "name": "good-step",
                        "expected_command": ["{GOOD}"],
                        "expected_materials": [["CREATE", "{GOOD}"]],
                        "expected_products": [["CREATE", "{GOOD}"]],
                    }
                ],
                "inspect": [
                    {
                        "name": "bad-inspection",
                        "run": ["{MISSING}"],
                        "expected_materials": [["CREATE", "{GOOD}"]],
                        "expected_products": [],
                    }
                ],
            }
        )

    def test_failure_in_inspection_keeps_step_unsubstituted(self):
        with self.assertRaises(ParameterSubstitutionError):
            substitute_parameters(self.layout, {"GOOD": "ok"}, strict=True)

        step = self.layout.steps[0]
        self.assertEqual(step.expected_command[0], "{GOOD}")
        self.assertEqual(step.expected_materials[0][1], "{GOOD}")
        self.assertEqual(step.expected_products[0][1], "{GOOD}")
        self.assertEqual(self.layout.inspect[0].run[0], "{MISSING}")
        self.assertEqual(
            self.layout.inspect[0].expected_materials[0][1], "{GOOD}"
        )

    def test_failure_in_step_keeps_inspection_unsubstituted(self):
        self.layout.inspect[0].run = ["{GOOD}"]
        self.layout.steps[0].expected_command = ["{MISSING}"]

        with self.assertRaises(ParameterSubstitutionError):
            substitute_parameters(self.layout, {"GOOD": "ok"}, strict=True)

        self.assertEqual(self.layout.steps[0].expected_command[0], "{MISSING}")
        self.assertEqual(self.layout.inspect[0].run[0], "{GOOD}")


class TestStrictValueIsVerbatim(unittest.TestCase):
    """Values are inserted as a single field and never interpreted again."""

    def test_spaces_braces_and_separators_keep_token_boundaries(self):
        value = "artifacts/ release candidate {name}/v1"
        layout = Layout.read(
            {
                "_type": "layout",
                "steps": [
                    {
                        "name": "s",
                        "expected_command": ["deploy", "{ARTIFACT}"],
                        "expected_materials": [["CREATE", "{ARTIFACT}"]],
                        "expected_products": [],
                    }
                ],
                "inspect": [{"name": "i", "run": ["ls", "{ARTIFACT}"]}],
            }
        )
        substitute_parameters(layout, {"ARTIFACT": value}, strict=True)

        # The substituted field stays one token even though the value contains
        # spaces, path separators and braces: no extra argv or rule tokens.
        self.assertEqual(
            layout.steps[0].expected_command, ["deploy", value]
        )
        self.assertEqual(
            layout.steps[0].expected_materials[0], ["CREATE", value]
        )
        self.assertEqual(layout.inspect[0].run, ["ls", value])

    def test_value_containing_placeholder_is_not_reparsed(self):
        layout = Layout.read(
            {
                "_type": "layout",
                "steps": [{"name": "s", "expected_command": ["{OUTER}"]}],
                "inspect": [],
            }
        )
        # No parameter named INNER is supplied; a recursive implementation would
        # raise, but strict mode inserts the value verbatim in a single pass.
        substitute_parameters(layout, {"OUTER": "{INNER}"}, strict=True)
        self.assertEqual(layout.steps[0].expected_command[0], "{INNER}")


class TestLegacyAndStrictModesCoexist(unittest.TestCase):
    """The old str.format mode and the new strict mode remain available."""

    def setUp(self):
        self.params = {"X": "vim"}

    def _layout(self, template):
        return Layout.read(
            {
                "_type": "layout",
                "steps": [{"name": "s", "expected_command": [template]}],
                "inspect": [],
            }
        )

    def test_legacy_mode_remains_default(self):
        layout = self._layout("{X}")
        substitute_parameters(layout, self.params)
        self.assertEqual(layout.steps[0].expected_command[0], "vim")

    def test_legacy_mode_still_accepts_format_syntax(self):
        # str.format features that strict mode must reject still work in legacy.
        layout = self._layout("{X!r}")
        substitute_parameters(layout, self.params)
        self.assertEqual(layout.steps[0].expected_command[0], "'vim'")

    def test_strict_mode_rejects_what_legacy_accepts(self):
        template = "{X!r}"
        legacy_layout = self._layout(template)
        substitute_parameters(legacy_layout, self.params)
        self.assertEqual(legacy_layout.steps[0].expected_command[0], "'vim'")

        strict_layout = self._layout(template)
        with self.assertRaises(ParameterSubstitutionError):
            substitute_parameters(strict_layout, self.params, strict=True)
        self.assertEqual(strict_layout.steps[0].expected_command[0], template)

    def test_legacy_missing_parameter_still_raises_keyerror(self):
        with self.assertRaises(KeyError):
            substitute_parameters(self._layout("{NOPE}"), {})


class TestStrictSubstituteOnVerify(unittest.TestCase, TmpDirMixin):
    """in_toto_verify authenticates the signed layout before substituting."""

    @classmethod
    def setUpClass(cls):
        cls.alice = SignerStore.rsa
        cls.alice_pub_dict = {
            SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub
        }

    def _signed_layout(self, command_template="{EDITOR}"):
        layout = Layout.read(
            {
                "_type": "layout",
                "inspect": [],
                "steps": [
                    {
                        "name": "run-command",
                        "expected_command": [command_template],
                    }
                ],
            }
        )
        metadata = Metablock(signed=layout)
        metadata.create_signature(self.alice)
        return metadata, layout

    def test_strict_substitution_runs_through_in_toto_verify(self):
        metadata, layout = self._signed_layout()
        with self.assertRaises(in_toto.exceptions.LinkNotFoundError):
            in_toto_verify(
                metadata,
                self.alice_pub_dict,
                substitution_parameters={"EDITOR": "vim"},
                strict=True,
            )
        self.assertEqual(layout.steps[0].expected_command[0], "vim")

    def test_strict_failure_leaves_layout_unsubstituted(self):
        metadata, layout = self._signed_layout("{EDITOR.bad}")
        with self.assertRaises(ParameterSubstitutionError):
            in_toto_verify(
                metadata,
                self.alice_pub_dict,
                substitution_parameters={"EDITOR": "vim"},
                strict=True,
            )
        self.assertEqual(layout.steps[0].expected_command[0], "{EDITOR.bad}")

    def test_signature_is_verified_before_substitution(self):
        metadata, layout = self._signed_layout("{MISSING}")
        # A bad verification key must fail signature authentication first, even
        # though strict substitution would also fail on the missing parameter.
        other_pub_dict = {
            SignerStore.ecdsa_pub["keyid"]: SignerStore.ecdsa_pub
        }
        with self.assertRaises(in_toto.exceptions.SignatureVerificationError):
            in_toto_verify(
                metadata,
                other_pub_dict,
                substitution_parameters={"MISSING": "x"},
                strict=True,
            )
        self.assertEqual(layout.steps[0].expected_command[0], "{MISSING}")


class TestStrictSubstitutionSublayoutScope(unittest.TestCase, TmpDirMixin):
    """Parameters and strict mode are scoped per layout, not inherited by
    sublayouts (which are verified independently against their own signature).
    """

    def test_superlayout_parameters_do_not_leak_into_sublayout(self):
        self.set_up_test_dir()
        try:
            alice = SignerStore.rsa
            alice_pub = SignerStore.rsa_pub
            bob = SignerStore.ecdsa
            bob_pub = SignerStore.ecdsa_pub

            root_step_name = "delegated-to-bob"

            # Sublayout: an inspection with a placeholder of its own and no
            # steps, so verification needs no link files. The command stays
            # harmless regardless of whether its placeholder is substituted.
            sublayout = Metablock(
                signed=Layout(
                    inspect=[
                        Inspection(
                            name="sub-inspection",
                            run=["python3", "-c", "pass", "{SUB_VAR}"],
                        )
                    ]
                )
            )
            sublayout.create_signature(bob)

            sub_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
                name=root_step_name, keyid=bob_pub["keyid"]
            )
            os.mkdir(sub_link_dir)
            # The root layout loads the sublayout as its step's link from the
            # top-level link dir; the sublayout's own links live in the subdir.
            sublayout.dump(
                FILENAME_FORMAT.format(
                    step_name=root_step_name, keyid=bob_pub["keyid"]
                )
            )

            # Root layout delegates the only step to the sublayout and carries
            # its own placeholder in an inspection.
            root_layout = Layout(
                keys={bob_pub["keyid"]: bob_pub},
                steps=[
                    Step(
                        name=root_step_name,
                        pubkeys=[bob_pub["keyid"]],
                    )
                ],
                inspect=[
                    Inspection(
                        name="root-inspection",
                        run=["python3", "-c", "pass", "{ROOT_VAR}"],
                    )
                ],
            )
            root_metadata = Metablock(signed=root_layout)
            root_metadata.create_signature(alice)

            in_toto_verify(
                root_metadata,
                {alice_pub["keyid"]: alice_pub},
                substitution_parameters={"ROOT_VAR": "root-value"},
                strict=True,
            )

            # The root layout placeholder is substituted ...
            self.assertEqual(
                root_layout.inspect[0].run,
                ["python3", "-c", "pass", "root-value"],
            )
            # ... but the sublayout has its own scope and is never passed the
            # root parameters, so its signed placeholder remains untouched.
            self.assertEqual(
                sublayout.get_payload().inspect[0].run,
                ["python3", "-c", "pass", "{SUB_VAR}"],
            )
        finally:
            self.tear_down_test_dir()


if __name__ == "__main__":
    unittest.main()
