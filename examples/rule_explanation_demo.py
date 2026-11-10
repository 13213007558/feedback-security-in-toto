# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
Machine-readable artifact rule explanation: end-to-end demo.

This script builds a small, in-memory supply chain that intentionally contains
every interesting rule situation and then replays its artifact rules with
``in_toto.rule_explainer.RuleExplainer``:

  * a rename / relocation authorized by a prefix MATCH,
  * a same-named file whose content changed (MODIFY, plus a MATCH whose
    destination digest mismatches),
  * a cross-step MATCH that succeeds,
  * a MATCH whose destination artifact does not exist,
  * a terminal DISALLOW that rejects the release because one artifact was
    never consumed.

It prints two reports:

  1. a full JSON report, and
  2. a report filtered to a single artifact, showing that unselected rules
     still run and consume artifacts while only the selected artifact's
     hashes and judgments are emitted.

Run it with:

    python examples/rule_explanation_demo.py
"""

import hashlib
import json

from in_toto.exceptions import RuleVerificationError
from in_toto.models.link import Link
from in_toto.rule_explainer import (
    PROVENANCE_INSPECTION,
    PROVENANCE_SIGNATURE_VERIFIED,
    RuleExplainer,
    RuleVerificationReport,
)


def hash_of(content):
    """Return a securesystemslib-style hash dict for some bytes."""
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha512": hashlib.sha512(content).hexdigest(),
    }


# ---------------------------------------------------------------------------
# A virtual file system: {step_name: {"materials": {...}, "products": {...}}}
# where every artifact maps to its hash dict.
# ---------------------------------------------------------------------------
# "config.ini" keeps identical content across steps.
# "src/app.py" is modified in place (same name, different digest).
# "src/legacy.txt" is relocated (renamed) to "staging/legacy.txt".
# "src/orphan.txt" is never authorized by any rule and trips DISALLOW.
config_v1 = b"[server]\nport=8080\n"
app_v1 = b"print('hello')\n"
app_v2 = b"print('hello, world')\n"
legacy = b"legacy payload\n"
orphan = b"nobody claims me\n"

links = {
    # Step 1: authoring. Produces the sources.
    "write-code": Link(
        name="write-code",
        materials={},
        products={
            "config.ini": hash_of(config_v1),
            "src/app.py": hash_of(app_v1),
            "src/legacy.txt": hash_of(legacy),
            "src/orphan.txt": hash_of(orphan),
        },
    ),
    # Step 2: packaging. Modifies app.py, relocates legacy.txt, and carries
    # config.ini through unchanged.
    "package": Link(
        name="package",
        materials={
            "config.ini": hash_of(config_v1),
            "src/app.py": hash_of(app_v1),
            "src/legacy.txt": hash_of(legacy),
            "src/orphan.txt": hash_of(orphan),
        },
        products={
            "config.ini": hash_of(config_v1),
            "src/app.py": hash_of(app_v2),
            "staging/legacy.txt": hash_of(legacy),
            "src/orphan.txt": hash_of(orphan),
        },
    ),
    # Inspection: re-derives the inputs. It only knows the unchanged config
    # and the *original* app.py, which lets us show a digest mismatch MATCH.
    "inspect": Link(
        name="inspect",
        materials={
            "config.ini": hash_of(config_v1),
            "src/app.py": hash_of(app_v1),
        },
        products={},
    ),
}

# Only step links carry verified signatures. The inspection link is generated
# locally during verification, so it must never be marked signature-verified.
link_provenance = {
    "write-code": PROVENANCE_SIGNATURE_VERIFIED,
    "package": PROVENANCE_SIGNATURE_VERIFIED,
    "inspect": PROVENANCE_INSPECTION,
}


# Product rules of the "package" step, in execution order.
package_product_rules = [
    # Cross-step MATCH against the inspection. app.py is still in the queue and
    # exists in the inspection materials, but with the original digest ->
    # digest-mismatch, so it is NOT consumed. This has to run before MODIFY
    # below, otherwise MODIFY would already have removed app.py from the queue.
    [
        "MATCH",
        "app.py",
        "IN",
        "src",
        "WITH",
        "MATERIALS",
        "IN",
        "src",
        "FROM",
        "inspect",
    ],
    # app.py kept its name but changed content -> MODIFY now consumes it.
    ["MODIFY", "src/app.py"],
    # legacy.txt moved from src/ to staging/ with identical bytes. The prefix
    # MATCH authorizes the relocation against the write-code step.
    [
        "MATCH",
        "legacy.txt",
        "IN",
        "staging",
        "WITH",
        "PRODUCTS",
        "IN",
        "src",
        "FROM",
        "write-code",
    ],
    # config.ini is unchanged and must equal the write-code product.
    [
        "MATCH",
        "config.ini",
        "WITH",
        "PRODUCTS",
        "FROM",
        "write-code",
    ],
    # A MATCH whose destination artifact is absent. The source candidate
    # src/orphan.txt is in the queue, but the write-code step has no product
    # under quarantine/ -> destination-missing, so nothing is consumed.
    [
        "MATCH",
        "orphan.txt",
        "IN",
        "src",
        "WITH",
        "PRODUCTS",
        "IN",
        "quarantine",
        "FROM",
        "write-code",
    ],
    # Terminal DISALLOW: src/orphan.txt was never consumed -> release rejected.
    ["DISALLOW", "*"],
]

# Material rules of the "package" step, showing REQUIRE and a cross-step
# MATCH. REQUIRE does not consume artifacts, so it runs before the MATCH that
# empties the queue.
package_material_rules = [
    ["REQUIRE", "config.ini"],
    # Everything the package step used must be traceable to write-code.
    [
        "MATCH",
        "*",
        "WITH",
        "PRODUCTS",
        "FROM",
        "write-code",
    ],
    ["DISALLOW", "*"],
]


def run(rules, source_type, artifact_filter=None):
    report = RuleVerificationReport()
    explainer = RuleExplainer(
        links,
        link_provenance=link_provenance,
        artifact_filter=artifact_filter,
    )
    try:
        explainer.explain_item_rules(
            report, "package", source_type, rules
        )
        outcome = "PASSED"
    except RuleVerificationError as error:
        outcome = f"FAILED: {error}"
    return report, outcome


def trace_artifact(report, item_name, source_type, artifact):
    """Print the rule-by-rule evidence path of one artifact."""
    item = report.get_item(item_name, source_type)
    print(f"\nEvidence trail for '{artifact}' in {item_name}/{source_type}")
    print("-" * 72)
    for rule in item.rule_explanations:
        for judgment in rule.judgments:
            if judgment.path == artifact:
                print(
                    f"  rule {rule.rule_index} {' '.join(rule.rule):<45}"
                    f"-> {judgment.outcome}"
                    + (f" ({judgment.reason})" if judgment.reason else "")
                )
        for match in rule.matches:
            if match.source_path == artifact:
                print(
                    f"  rule {rule.rule_index} {' '.join(rule.rule):<45}"
                    f"-> {match.outcome} "
                    f"[src={match.source_path} "
                    f"dest={match.destination_name}:{match.destination_path} "
                    f"algs={','.join(match.hash_algorithms)}]"
                )
    print(
        f"  link provenance: {item.link_provenance} "
        f"(trusted={item.link_trusted})"
    )


def main():
    print("=" * 72)
    print("FULL REPORT (all artifacts)")
    print("=" * 72)
    report, outcome = run(package_product_rules, "products")
    print(f"verification outcome: {outcome}\n")
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))

    trace_artifact(
        report, "package", "products", "staging/legacy.txt"
    )
    trace_artifact(report, "package", "products", "src/app.py")
    trace_artifact(report, "package", "products", "src/orphan.txt")

    print("\n" + "=" * 72)
    print("FILTERED REPORT (only 'src/app.py')")
    print("=" * 72)
    filtered, filtered_outcome = run(
        package_product_rules,
        "products",
        artifact_filter={"src/app.py"},
    )
    print(f"verification outcome: {filtered_outcome}")
    filtered_item = filtered.get_item("package", "products")
    disallow = filtered_item.rule_explanations[-1]
    print(
        "\nTerminal DISALLOW still runs and still fails, but its detailed\n"
        f"judgment list is empty for the filtered view: {disallow.judgments}\n"
        f"while the complete queue snapshot is retained: "
        f"{disallow.queue_before}"
    )
    print("\nFiltered JSON:\n")
    print(json.dumps(filtered.to_dict(), indent=2, sort_keys=True))

    print("\n" + "=" * 72)
    print("MATERIAL RULES (cross-step MATCH + REQUIRE)")
    print("=" * 72)
    material_report, material_outcome = run(
        package_material_rules, "materials"
    )
    print(f"verification outcome: {material_outcome}")
    print(json.dumps(material_report.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
