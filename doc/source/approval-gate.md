# Two-Phase Inspection Approval

By default `in_toto.verifylib.in_toto_verify` runs every inspection command
immediately after the static checks pass. In some environments a security
reviewer must see the exact command arguments and artifact rules *before* any
inspection is allowed to execute. `in_toto.approval` splits that flow into two
phases without introducing a separate approval service.

## Phase 1: prepare a plan

`in_toto.approval.prepare_inspection_plan` performs only the read-only parts of
verification:

1. verify the layout signatures against the trusted key configuration,
2. verify the layout has not expired,
3. perform parameter substitution (the plan is only produced if substitution
   succeeds),
4. load links and verify link signature thresholds, and
5. expand sublayouts, each becoming its own plan level.

It returns an `~in_toto.approval.InspectionPlan`. The preparation phase never
executes a command; it does not even accept an executor. For each layout level
the plan lists, in the original order:

* the substituted inspection command as an **argument array** (never a shell
  string),
* the working directory constraint, and
* the material and product artifact rules.

Each level also records the digest of the raw, pre-substitution signed layout
bytes, a digest of the trusted key configuration, and the substitution
parameters.

## Review with a local callback

`in_toto.approval.approve_plan` invokes a local admission callback once per
layout level. The callback receives an `~in_toto.approval.LayoutLevelPlan` and
returns a boolean. The returned `~in_toto.approval.Approval` binds the layout
byte digest, key configuration digest, parameters, expiration and an
inspection-list digest for that level.

Sublayout inspections are never covered by a top-level decision: every
expanded sublayout is a separate level that must be approved on its own.

## Phase 2: execute after approval

`in_toto.approval.execute_inspection_plan` re-loads the exact signed layout
bytes captured during planning, re-runs signature and expiration checks,
re-applies parameter substitution, and re-checks every approval binding before
running anything. An `~in_toto.approval.ApprovalError` is raised, without
calling the executor, when:

* a level was rejected or has no approval,
* the layout bytes, trusted keys, parameters, expiration or inspection list
  changed after approval, or
* the set of expanded sublayout levels changed.

An `~in_toto.approval.InspectionExecutor` receives each command as an array
plus the approved working directory. `RealInspectionExecutor` records
artifacts and runs the command through `in_toto.runlib.in_toto_run`, while
`FakeInspectionExecutor` counts calls and returns caller-provided links for
tests and demos without spawning a subprocess.

A complete, runnable integration using the fake executor lives in
`examples/approval_demo.py`.

## API

```{eval-rst}
.. autofunction:: in_toto.approval.prepare_inspection_plan
.. autofunction:: in_toto.approval.approve_plan
.. autofunction:: in_toto.approval.execute_inspection_plan
.. autoclass:: in_toto.approval.InspectionPlan
.. autoclass:: in_toto.approval.LayoutLevelPlan
.. autoclass:: in_toto.approval.InspectionPlanEntry
.. autoclass:: in_toto.approval.Approval
.. autoclass:: in_toto.approval.RealInspectionExecutor
.. autoclass:: in_toto.approval.FakeInspectionExecutor
```
