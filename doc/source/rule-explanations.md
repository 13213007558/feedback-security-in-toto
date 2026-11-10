# Artifact Rule Explanations

When a release is rejected by an in-toto artifact rule, it can be hard to tell
*which* rule consumed a given artifact, or why an artifact was never matched.
`in_toto.rule_explainer` produces a machine-readable explanation of the whole
rule verification process so that a reader can follow a single artifact from
the initial materials/products to the rule that judged it, without enabling
global debug logging.

## How it relates to verification

The explainer replays the exact semantics implemented in
{func}`in_toto.verifylib.verify_item_rules`:

- the same initial artifact queue (all materials or all products of the item),
- the same rules in the same order,
- the same glob filtering, prefix transformation and set operations,
- the same consumption behavior — an artifact is removed from the queue only
  when a rule successfully consumes it.

Producing an explanation therefore never changes which artifacts get consumed
or whether verification passes. On failure, the report keeps every rule up to
and including the failing one.

## Collecting a report during verification

Pass a `RuleVerificationReport` to {func}`in_toto.verifylib.in_toto_verify`
(or to `verify_all_item_rules` / `verify_item_rules`):

```python
from in_toto.rule_explainer import RuleVerificationReport
from in_toto.verifylib import in_toto_verify
from in_toto.exceptions import RuleVerificationError

report = RuleVerificationReport()
try:
    in_toto_verify(metadata, layout_keys, report=report)
except RuleVerificationError:
    # The report still contains everything up to the failing rule.
    print(report.to_json())
```

## Trust of link data

The explainer never promotes link data to a trusted source on its own. Each
item explanation carries:

- `link_provenance`: one of
  - `"signature-verified"` — the link signature was verified before its
    artifacts were used,
  - `"inspection"` — the link was generated locally by running an inspection,
  - `"unverified"` — no signature result is known (the default).
- `link_trusted`: `true` only for `"signature-verified"` provenance.

When using `in_toto_verify`, step links are labeled
`"signature-verified"` because signature threshold verification runs before
the rules, while inspection links are labeled `"inspection"`. When driving the
`RuleExplainer` directly, you must supply the provenance mapping yourself;
anything you do not explicitly label stays `"unverified"`.

## Report structure

The report is a list of item explanations, one per step/inspection and
`materials`/`products` pair. Each item records its initial materials and
products and one `rule_explanations` entry per executed rule.

Every rule entry contains:

- `rule`, `rule_type`, `pattern` and `rule_index`,
- `queue_before` and `queue_after`: the complete, sorted queue snapshots
  surrounding the rule,
- `consumed`: the artifacts the rule removed from the queue,
- `status` (`"passed"`/`"failed"`) and `error`,
- `judgments`: per-artifact results for CREATE, DELETE, MODIFY, ALLOW,
  DISALLOW and REQUIRE, each with an `outcome` (`"consumed"`/`"skipped"`) and
  a machine-readable `reason`,
- `matches`: per-artifact results for MATCH rules,
- `destination_link`: provenance of the destination link (or `null`).

### MATCH details

Each MATCH entry keeps the information needed to reconstruct the comparison:

- `source_path` — full source path, including the source prefix,
- `destination_path` — the path looked up in the destination link after the
  prefix transformation,
- `source_prefix` / `destination_prefix`,
- `destination_name` and `destination_type` (the target step and whether its
  materials or products were used),
- `hash_algorithms` — algorithms that participated in the comparison,
- `source_hashes` and `destination_hashes`,
- `outcome`, which distinguishes the two ways a MATCH can fail:
  - `"destination-missing"` — no artifact exists at `destination_path`,
  - `"digest-mismatch"` — an artifact of that name exists but at least one
    digest differs,
  - `"matched"` — the digests are equal and the artifact is consumed.

## Filtering to specific artifacts

Large layouts may carry many artifacts. Pass `artifact_filter` to limit the
detailed per-artifact evidence (hashes, judgments and MATCH entries) to the
paths you care about:

```python
report = RuleVerificationReport()
in_toto_verify(
    metadata,
    layout_keys,
    report=report,
    artifact_filter={"src/app.py"},
)
```

Filtering only changes what is *emitted*. Every rule still runs and consumes
artifacts, and `queue_before`/`queue_after` always contain the complete queue,
so the result of verification is unaffected.

## End-to-end example

`examples/rule_explanation_demo.py` builds an in-memory pipeline containing a
rename/relocation (prefix MATCH), a same-named file whose content changed
(MODIFY plus a digest-mismatch MATCH), a successful cross-step MATCH, a MATCH
whose destination artifact is missing and a terminal DISALLOW that rejects the
release. It prints both a full report and a filtered report:

```shell
python examples/rule_explanation_demo.py
```

## API reference

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.RuleExplainer
  :members:
  :special-members: __init__
```

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.RuleVerificationReport
  :members:
```

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.ItemExplanation
  :members:
```

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.RuleExplanation
  :members:
```

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.MatchExplanation
  :members:
```

```{eval-rst}
.. autoclass:: in_toto.rule_explainer.ArtifactJudgment
  :members:
```
