# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Module Name>
  in_toto/rule_explainer.py

<Purpose>
  Provides machine-readable explanations for in-toto artifact rule
  verification.

  The explanations are produced by replaying the exact rule semantics
  implemented in ``in_toto.verifylib`` (same glob filtering, prefix
  transformation, set operations and consumption order) and recording, for
  every rule of every step/inspection:

    - the artifact queue before and after the rule ran,
    - the artifacts the rule judged and the per-artifact judgment,
    - for MATCH rules, the source path, the prefix-transformed destination
      path, the destination step, the compared hash algorithms, and a
      distinction between a missing destination artifact and a same-named
      artifact with a mismatching digest.

  The explanations never alter the consumption order of the regular
  verification. Rules that are not part of a requested artifact filter are
  still executed and still consume artifacts; only their detailed per-artifact
  judgments are left out of the report. Link data is never promoted to a
  trusted source by this module: each referenced link's provenance is carried
  along explicitly and defaults to ``"unverified"``.
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Optional

import securesystemslib.exceptions

import in_toto.rulelib
from in_toto.exceptions import RuleVerificationError

# Rule types (lower case, as returned by ``rulelib.unpack_rule``).
RULE_CREATE = "create"
RULE_DELETE = "delete"
RULE_MODIFY = "modify"
RULE_ALLOW = "allow"
RULE_DISALLOW = "disallow"
RULE_REQUIRE = "require"
RULE_MATCH = "match"

# Per-artifact judgment of a generic rule.
OUTCOME_CONSUMED = "consumed"
OUTCOME_SKIPPED = "skipped"

# Judgment of a whole rule.
RULE_PASSED = "passed"
RULE_FAILED = "failed"

# Per-artifact judgment of a MATCH rule.
MATCH_MATCHED = "matched"
MATCH_MISSING_DESTINATION = "destination-missing"
MATCH_DIGEST_MISMATCH = "digest-mismatch"

# Provenance of the link data an explanation is built from.
# - "signature-verified": the link signature was successfully verified before
#   its artifacts were used as evidence.
# - "inspection": the link was generated locally by running an inspection
#   command during verification.
# - "unverified": no signature verification result is known. Artifacts of such
#   links must never be treated as trusted evidence.
PROVENANCE_SIGNATURE_VERIFIED = "signature-verified"
PROVENANCE_INSPECTION = "inspection"
PROVENANCE_UNVERIFIED = "unverified"

_LINK_PROVENANCE = {
    PROVENANCE_SIGNATURE_VERIFIED,
    PROVENANCE_INSPECTION,
    PROVENANCE_UNVERIFIED,
}


@dataclass
class MatchExplanation:
    """Record of a single source artifact judged by a MATCH rule.

    Attributes:
      source_path: Path of the source artifact, including the source prefix.
      destination_path: Path looked up in the destination link, including the
          destination prefix (prefix transformation applied to ``source_path``).
      destination_name: Name of the step/inspection the rule matches against.
      destination_type: ``"materials"`` or ``"products"`` of the destination
          link.
      source_prefix: Source prefix stripped before glob filtering.
      destination_prefix: Destination prefix prepended for the destination
          lookup.
      hash_algorithms: Hash algorithm names that participated in the
          comparison (union of source and destination hash dict keys).
      outcome: One of the ``MATCH_*`` constants. ``matched`` means the
          artifact was consumed; ``destination-missing`` means no artifact
          exists at ``destination_path``; ``digest-mismatch`` means an
          artifact of that name exists but at least one digest differs.
      source_hashes: Hash dict of the source artifact, or ``None`` if this
          artifact is excluded by the report filter.
      destination_hashes: Hash dict found in the destination link, or
          ``None`` for a missing destination or an excluded artifact.
    """

    source_path: str
    destination_path: str
    destination_name: str
    destination_type: str
    source_prefix: str
    destination_prefix: str
    hash_algorithms: list
    outcome: str
    source_hashes: Optional[dict] = None
    destination_hashes: Optional[dict] = None


@dataclass
class ArtifactJudgment:
    """Per-artifact judgment recorded by a non-MATCH rule.

    Attributes:
      path: The judged artifact path.
      outcome: ``"consumed"`` (removed from the queue) or ``"skipped"`` (left
          in the queue because the rule's condition did not hold).
      reason: Short machine-readable reason for a skip, e.g.
          ``"in-materials"`` for CREATE or ``"same-digest"`` for MODIFY. It is
          ``None`` for consumed artifacts.
      hashes: Hash dict of the artifact, or ``None`` if excluded by the report
          filter. Generic rules reason over path membership; hashes are only
          attached for MODIFY to evidence a digest change.
    """

    path: str
    outcome: str
    reason: Optional[str] = None
    hashes: Optional[dict] = None


@dataclass
class RuleExplanation:
    """Explanation of one artifact rule execution.

    Attributes:
      rule_index: Zero-based position of the rule in the item's rule list.
      rule: The original rule token list.
      rule_type: Lower-case rule type (see ``RULE_*`` constants).
      pattern: Rule pattern (for REQUIRE, the literal required file name).
      queue_before: Sorted artifact paths remaining in the queue before the
          rule ran. Always complete, independent of the artifact filter.
      queue_after: Sorted artifact paths remaining after the rule ran. Always
          complete, independent of the artifact filter.
      consumed: Sorted paths consumed by the rule.
      status: ``"passed"`` or ``"failed"`` (only DISALLOW and REQUIRE fail).
      error: Error message of a failed rule, otherwise ``None``.
      judgments: Per-artifact judgments for generic rules, restricted to
          included artifacts when a filter is active.
      matches: Per-artifact MATCH explanations, restricted to included
          artifacts when a filter is active.
      destination_link: For MATCH, provenance info for the destination link,
          or ``None`` if the destination link is absent.
    """

    rule_index: int
    rule: list
    rule_type: str
    pattern: str
    queue_before: list
    queue_after: list = field(default_factory=list)
    consumed: list = field(default_factory=list)
    status: str = RULE_PASSED
    error: Optional[str] = None
    judgments: list = field(default_factory=list)
    matches: list = field(default_factory=list)
    destination_link: Optional[dict] = None


@dataclass
class ItemExplanation:
    """Explanation of the material or product rules of one item.

    Attributes:
      item_name: Name of the step or inspection.
      source_type: ``"materials"`` or ``"products"``.
      initial_materials: All material paths reported by the item's link.
      initial_products: All product paths reported by the item's link.
      link_provenance: Provenance of the item's own link (see ``PROVENANCE_*``).
      link_trusted: ``True`` only if the item's link was signature-verified.
      rule_explanations: One entry per executed rule, in execution order. On
          failure the failing rule is the last entry and carries the error.
      failed: Whether rule processing raised for this item.
      failure_message: The raised error message, if ``failed`` is ``True``.
    """

    item_name: str
    source_type: str
    initial_materials: list
    initial_products: list
    link_provenance: str
    link_trusted: bool
    rule_explanations: list = field(default_factory=list)
    failed: bool = False
    failure_message: Optional[str] = None


@dataclass
class RuleVerificationReport:
    """Machine-readable report covering one or more items' rule verification.

    The report is JSON serializable via :py:meth:`to_dict` and
    :py:meth:`to_json`.
    """

    items: list = field(default_factory=list)

    def add_item(self, item_explanation):
        """Append an :class:`ItemExplanation` to the report."""
        self.items.append(item_explanation)

    def get_item(self, item_name, source_type):
        """Return the item explanation, or ``None`` if not present."""
        for item in self.items:
            if (
                item.item_name == item_name
                and item.source_type == source_type
            ):
                return item
        return None

    def to_dict(self):
        """Return a plain ``dict`` representation (sets become sorted lists)."""
        return asdict(self)

    def to_json(self, indent=2):
        """Return a stable, indented JSON string of the report."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class RuleExplainer:
    """Replay artifact rules while recording machine-readable explanations.

    Arguments:
      links: A dictionary of link metadata per item name, as used by
          ``verifylib.verify_item_rules``.
      link_provenance: Optional mapping of item name to one of the
          ``PROVENANCE_*`` constants. Items absent from the mapping are
          reported as ``"unverified"`` and are never marked trusted.
      artifact_filter: Optional iterable of artifact paths. Only these
          artifacts get per-artifact evidence (hashes, judgments, MATCH
          details). All rules still run and all queue snapshots stay
          complete. ``None`` (the default) includes every artifact.
    """

    def __init__(
        self, links, link_provenance=None, artifact_filter=None
    ):
        self.links = links
        self.link_provenance = link_provenance or {}
        for name, provenance in self.link_provenance.items():
            if provenance not in _LINK_PROVENANCE:
                raise ValueError(
                    f"Unknown link provenance '{provenance}' for link "
                    f"'{name}'. Expected one of {sorted(_LINK_PROVENANCE)}."
                )

        if artifact_filter is None:
            self.artifact_filter = None
        else:
            self.artifact_filter = set(artifact_filter)

    def _provenance_of(self, name):
        return self.link_provenance.get(name, PROVENANCE_UNVERIFIED)

    def _is_trusted(self, name):
        return self._provenance_of(name) == PROVENANCE_SIGNATURE_VERIFIED

    def _is_included(self, path):
        """Whether detailed evidence for ``path`` should be emitted."""
        if self.artifact_filter is None:
            return True
        return path in self.artifact_filter

    def _hash_dict(self, artifacts, path):
        """Hash dict for ``path`` or ``None`` if excluded/unavailable."""
        if not self._is_included(path):
            return None
        return dict(artifacts.get(path, {}))

    def _link_info(self, name, artifact_type):
        """Provenance descriptor for a referenced link."""
        link = self.links.get(name)
        if link is None:
            return None
        return {
            "name": name,
            "artifact_type": artifact_type,
            "provenance": self._provenance_of(name),
            "trusted": self._is_trusted(name),
        }

    def explain_item_rules(
        self, report, source_name, source_type, rules
    ):
        """Run the rules of one item and append an explanation to ``report``.

        Mirrors ``verifylib.verify_item_rules``: the same queue, the same
        rule order and the same consumption semantics. On failure the report
        keeps every rule up to and including the failing one before the
        exception is re-raised.

        Raises:
          securesystemslib.exceptions.FormatError: For an invalid source type
              or malformed rule.
          RuleVerificationError: On a failing DISALLOW or REQUIRE rule.
        """
        if source_type not in {"materials", "products"}:
            raise securesystemslib.exceptions.FormatError(
                "Argument 'source_type' of 'explain_item_rules' has to be "
                f"one of 'materials' or 'products'. Got: '{source_type}'"
            )

        link = self.links[source_name]
        materials_dict = link.materials
        products_dict = link.products
        materials_paths = set(materials_dict.keys())
        products_paths = set(products_dict.keys())

        source_artifacts = getattr(link, source_type)
        artifacts_queue = set(source_artifacts.keys())

        item = ItemExplanation(
            item_name=source_name,
            source_type=source_type,
            initial_materials=sorted(materials_dict.keys()),
            initial_products=sorted(products_dict.keys()),
            link_provenance=self._provenance_of(source_name),
            link_trusted=self._is_trusted(source_name),
        )
        report.add_item(item)

        try:
            for rule_index, rule in enumerate(rules):
                rule_data = in_toto.rulelib.unpack_rule(rule)
                rule_type = rule_data["rule_type"]
                pattern = rule_data["pattern"]

                explanation = RuleExplanation(
                    rule_index=rule_index,
                    rule=list(rule),
                    rule_type=rule_type,
                    pattern=pattern,
                    queue_before=sorted(artifacts_queue),
                )
                # Append before execution so the explanation is retained in
                # the report even if the rule fails and raises.
                item.rule_explanations.append(explanation)

                if rule_type == RULE_MATCH:
                    consumed = self._explain_match(
                        rule_data,
                        artifacts_queue,
                        source_artifacts,
                        explanation,
                    )
                elif rule_type == RULE_CREATE:
                    consumed = self._explain_create(
                        pattern,
                        artifacts_queue,
                        materials_paths,
                        products_paths,
                        explanation,
                    )
                elif rule_type == RULE_DELETE:
                    consumed = self._explain_delete(
                        pattern,
                        artifacts_queue,
                        materials_paths,
                        products_paths,
                        explanation,
                    )
                elif rule_type == RULE_MODIFY:
                    consumed = self._explain_modify(
                        pattern,
                        artifacts_queue,
                        materials_dict,
                        products_dict,
                        explanation,
                    )
                elif rule_type == RULE_ALLOW:
                    consumed = self._explain_allow(
                        pattern, artifacts_queue, explanation
                    )
                elif rule_type == RULE_DISALLOW:
                    consumed = self._explain_disallow(
                        pattern, artifacts_queue, explanation
                    )
                elif rule_type == RULE_REQUIRE:
                    consumed = self._explain_require(
                        pattern, artifacts_queue, explanation
                    )
                else:  # pragma: no cover (unreachable, unpack_rule guards)
                    raise securesystemslib.exceptions.FormatError(
                        f"Invalid rule type '{rule_type}'."
                    )

                if explanation.status == RULE_FAILED:
                    raise RuleVerificationError(explanation.error)

                artifacts_queue -= consumed
                explanation.queue_after = sorted(artifacts_queue)
                explanation.consumed = sorted(consumed)

        except RuleVerificationError as error:
            item.failed = True
            item.failure_message = str(error)
            raise

        return item

    def _explain_create(
        self, pattern, queue, materials, products, explanation
    ):
        filtered = fnmatch.filter(sorted(queue), pattern)
        consumed = set()
        for path in filtered:
            if path in products and path not in materials:
                consumed.add(path)
                outcome, reason = OUTCOME_CONSUMED, None
            else:
                outcome = OUTCOME_SKIPPED
                if path in materials:
                    reason = "in-materials"
                else:
                    reason = "not-in-products"
            if self._is_included(path):
                explanation.judgments.append(
                    ArtifactJudgment(path=path, outcome=outcome, reason=reason)
                )
        return consumed

    def _explain_delete(
        self, pattern, queue, materials, products, explanation
    ):
        filtered = fnmatch.filter(sorted(queue), pattern)
        consumed = set()
        for path in filtered:
            if path in materials and path not in products:
                consumed.add(path)
                outcome, reason = OUTCOME_CONSUMED, None
            else:
                outcome = OUTCOME_SKIPPED
                if path not in materials:
                    reason = "not-in-materials"
                else:
                    reason = "in-products"
            if self._is_included(path):
                explanation.judgments.append(
                    ArtifactJudgment(path=path, outcome=outcome, reason=reason)
                )
        return consumed

    def _explain_modify(
        self, pattern, queue, materials, products, explanation
    ):
        filtered = set(
            fnmatch.filter(sorted(queue), pattern)
        ) & set(materials.keys()) & set(products.keys())
        consumed = set()
        for path in sorted(filtered):
            if materials[path] != products[path]:
                consumed.add(path)
                outcome, reason = OUTCOME_CONSUMED, None
            else:
                outcome, reason = OUTCOME_SKIPPED, "same-digest"
            if self._is_included(path):
                explanation.judgments.append(
                    ArtifactJudgment(
                        path=path,
                        outcome=outcome,
                        reason=reason,
                        hashes={
                            "materials": self._hash_dict(materials, path),
                            "products": self._hash_dict(products, path),
                        },
                    )
                )
        return consumed

    def _explain_allow(self, pattern, queue, explanation):
        filtered = fnmatch.filter(sorted(queue), pattern)
        consumed = set(filtered)
        for path in filtered:
            if self._is_included(path):
                explanation.judgments.append(
                    ArtifactJudgment(path=path, outcome=OUTCOME_CONSUMED)
                )
        return consumed

    def _explain_disallow(self, pattern, queue, explanation):
        filtered = fnmatch.filter(sorted(queue), pattern)
        for path in filtered:
            if self._is_included(path):
                explanation.judgments.append(
                    ArtifactJudgment(
                        path=path,
                        outcome=OUTCOME_SKIPPED,
                        reason="disallowed",
                    )
                )
        if filtered:
            explanation.status = RULE_FAILED
            explanation.error = (
                f"'DISALLOW {pattern}' matched the following artifacts: "
                f"{filtered}"
            )
            explanation.queue_after = sorted(queue)
            explanation.consumed = []
        return set()

    def _explain_require(self, filename, queue, explanation):
        if filename not in queue:
            explanation.status = RULE_FAILED
            explanation.error = (
                f"'REQUIRE {filename}' did not find {filename} "
                f"in: {sorted(queue)}"
            )
            explanation.queue_after = sorted(queue)
            explanation.consumed = []
        elif self._is_included(filename):
            explanation.judgments.append(
                ArtifactJudgment(path=filename, outcome=OUTCOME_CONSUMED)
            )
        return set()

    def _explain_match(
        self, rule_data, queue, source_artifacts, explanation
    ):
        # Mirrors verifylib.verify_match_rule, including prefix handling.
        dest_name = rule_data["dest_name"]
        dest_type = rule_data["dest_type"]
        dest_link = self.links.get(dest_name)

        explanation.destination_link = self._link_info(
            dest_name, dest_type
        )

        if not dest_link:
            # No destination link: nothing can be consumed. Candidates that
            # the pattern would have selected are recorded as missing.
            self._record_match_without_destination(
                rule_data, queue, source_artifacts, explanation
            )
            return set()

        dest_artifacts = getattr(dest_link, dest_type)

        if rule_data["source_prefix"]:
            normalized_source_prefix = os.path.join(
                rule_data["source_prefix"], ""
            ).replace("\\", "/")
            filtered_source_paths = [
                path[len(normalized_source_prefix) :]
                for path in sorted(queue)
                if path.startswith(normalized_source_prefix)
            ]
        else:
            filtered_source_paths = sorted(queue)

        filtered_source_paths = fnmatch.filter(
            filtered_source_paths, rule_data["pattern"]
        )

        consumed = set()
        for path in filtered_source_paths:
            if rule_data["source_prefix"]:
                full_source_path = os.path.join(
                    rule_data["source_prefix"], path
                ).replace("\\", "/")
            else:
                full_source_path = path

            if rule_data["dest_prefix"]:
                full_dest_path = os.path.join(
                    rule_data["dest_prefix"], path
                ).replace("\\", "/")
            else:
                full_dest_path = path

            source_artifact = source_artifacts[full_source_path]
            include = self._is_included(full_source_path)

            try:
                dest_artifact = dest_artifacts[full_dest_path]
            except KeyError:
                if include:
                    explanation.matches.append(
                        MatchExplanation(
                            source_path=full_source_path,
                            destination_path=full_dest_path,
                            destination_name=dest_name,
                            destination_type=dest_type,
                            source_prefix=rule_data["source_prefix"],
                            destination_prefix=rule_data["dest_prefix"],
                            hash_algorithms=sorted(
                                source_artifact.keys()
                            ),
                            outcome=MATCH_MISSING_DESTINATION,
                            source_hashes=dict(source_artifact),
                            destination_hashes=None,
                        )
                    )
                continue

            algorithms = sorted(
                set(source_artifact.keys()) | set(dest_artifact.keys())
            )

            if source_artifact == dest_artifact:
                outcome = MATCH_MATCHED
                consumed.add(full_source_path)
            else:
                outcome = MATCH_DIGEST_MISMATCH

            if include:
                explanation.matches.append(
                    MatchExplanation(
                        source_path=full_source_path,
                        destination_path=full_dest_path,
                        destination_name=dest_name,
                        destination_type=dest_type,
                        source_prefix=rule_data["source_prefix"],
                        destination_prefix=rule_data["dest_prefix"],
                        hash_algorithms=algorithms,
                        outcome=outcome,
                        source_hashes=dict(source_artifact),
                        destination_hashes=dict(dest_artifact),
                    )
                )

        return consumed

    def _record_match_without_destination(
        self, rule_data, queue, source_artifacts, explanation
    ):
        """Record would-be MATCH candidates when the dest link is absent."""
        if rule_data["source_prefix"]:
            normalized_source_prefix = os.path.join(
                rule_data["source_prefix"], ""
            ).replace("\\", "/")
            filtered_source_paths = [
                path[len(normalized_source_prefix) :]
                for path in sorted(queue)
                if path.startswith(normalized_source_prefix)
            ]
        else:
            filtered_source_paths = sorted(queue)

        filtered_source_paths = fnmatch.filter(
            filtered_source_paths, rule_data["pattern"]
        )

        for path in filtered_source_paths:
            if rule_data["source_prefix"]:
                full_source_path = os.path.join(
                    rule_data["source_prefix"], path
                ).replace("\\", "/")
            else:
                full_source_path = path

            if rule_data["dest_prefix"]:
                full_dest_path = os.path.join(
                    rule_data["dest_prefix"], path
                ).replace("\\", "/")
            else:
                full_dest_path = path

            if not self._is_included(full_source_path):
                continue

            source_artifact = source_artifacts[full_source_path]
            explanation.matches.append(
                MatchExplanation(
                    source_path=full_source_path,
                    destination_path=full_dest_path,
                    destination_name=rule_data["dest_name"],
                    destination_type=rule_data["dest_type"],
                    source_prefix=rule_data["source_prefix"],
                    destination_prefix=rule_data["dest_prefix"],
                    hash_algorithms=sorted(source_artifact.keys()),
                    outcome=MATCH_MISSING_DESTINATION,
                    source_hashes=dict(source_artifact),
                    destination_hashes=None,
                )
            )
