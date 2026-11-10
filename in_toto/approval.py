# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  approval.py

<Purpose>
  Two-phase inspection verification with an explicit human approval gate.

  Phase 1 (planning, no command execution):
  ``prepare_inspection_plan`` performs every read-only part of normal in-toto
  verification -- layout signature verification, expiration check, parameter
  substitution, link loading and threshold checks, sublayout expansion -- and
  produces an :class:`InspectionPlan`. The plan lists, for every layout level
  (the top-level layout and each expanded sublayout), the in-order inspection
  command argument arrays, the working directory constraint and the material
  and product artifact rules that will be applied.

  Phase 2 (execution, only after approval):
  A security reviewer decides on the plan through a local admission callback
  (:class:`AdmissionCallback`). The resulting :class:`Approval` binds the raw
  layout byte digest, the trusted key configuration and the substitution
  parameters of every covered layout level. ``execute_inspection_plan``
  re-derives and re-checks all of these bindings, re-checks expiration, and
  only then invokes an :class:`InspectionExecutor`. Approvals never carry
  across sublayout boundaries: inspections discovered while expanding a
  sublayout require their own plan entries and approvals.

  The preparation phase never runs commands; it does not even accept an
  executor. Commands are always passed to the executor as argument arrays,
  never as shell strings.

"""

import copy
import hashlib
import json
import os
from typing import Callable, List, Optional

import attr
import securesystemslib.formats

import in_toto.models.layout
import in_toto.settings
import in_toto.verifylib
from in_toto.exceptions import ApprovalError
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata


def _canonical_json(data):
  """Deterministic byte encoding of JSON-serializable data."""
  return securesystemslib.formats.encode_canonical(data).encode("utf-8")


def _digest(data):
  """Return a hex digest over the canonical JSON encoding of ``data``."""
  return hashlib.sha256(_canonical_json(data)).hexdigest()


def _raw_layout_bytes(metadata):
  """Return the exact bytes that were signed for a layout.

  For traditional Metablocks these are the canonical JSON signable bytes; for
  DSSE envelopes these are the raw payload bytes.
  """
  if hasattr(metadata, "payload"):
    return metadata.payload
  return metadata.signed.signable_bytes


def _raw_layout_digest(metadata):
  """Digest of the signed layout bytes, computed before substitution mutates
  the in-memory layout object."""
  return hashlib.sha256(_raw_layout_bytes(metadata)).hexdigest()


def _key_config_digest(layout_key_dict):
  """Digest of the trusted verification key configuration.

  Any change to the set of trusted keys (addition, removal, changed key
  material or keyid) produces a different digest and thus invalidates an
  existing approval.
  """
  return _digest(layout_key_dict)


@attr.s(frozen=True)
class InspectionPlanEntry:
  """One inspection, after parameter substitution, ready for review.

  Attributes:
    name: The inspection name as defined in the layout.
    run: The substituted command and its arguments, kept as an ordered array.
    expected_materials: The substituted material artifact rules, in order.
    expected_products: The substituted product artifact rules, in order.
  """

  name = attr.ib(type=str)
  run = attr.ib(type=List[str])
  expected_materials = attr.ib(type=List[List[str]])
  expected_products = attr.ib(type=List[List[str]])

  def to_dict(self):
    return {
        "name": self.name,
        "run": list(self.run),
        "expected_materials": [list(rule) for rule in self.expected_materials],
        "expected_products": [list(rule) for rule in self.expected_products],
    }


@attr.s(frozen=True)
class LayoutLevelPlan:
  """Everything a reviewer must see for one layout in the (possibly nested)
  layout hierarchy.

  Attributes:
    level_id: Stable identifier of the level within the plan. The top-level
        layout uses an empty string; sublayouts use their delegation path,
        e.g. ``"delegated-step/keyid-prefix"``.
    layout_digest: Digest of the raw signed layout bytes before substitution.
    key_config_digest: Digest of the trusted verification key dictionary.
    substitution_parameters: The parameters applied to this layout level.
    expires: The layout expiration string (re-checked at execution time).
    workdir: Directory constraint relative to which inspections run.
    inspections: Ordered inspection entries of this layout level.
  """

  level_id = attr.ib(type=str)
  layout_digest = attr.ib(type=str)
  key_config_digest = attr.ib(type=str)
  substitution_parameters = attr.ib(type=Optional[dict])
  expires = attr.ib(type=str)
  workdir = attr.ib(type=str)
  inspections = attr.ib(type=List[InspectionPlanEntry])

  def to_dict(self):
    return {
        "level_id": self.level_id,
        "layout_digest": self.layout_digest,
        "key_config_digest": self.key_config_digest,
        "substitution_parameters": (
            dict(self.substitution_parameters)
            if self.substitution_parameters is not None
            else None
        ),
        "expires": self.expires,
        "workdir": self.workdir,
        "inspections": [entry.to_dict() for entry in self.inspections],
    }


@attr.s(frozen=True)
class Approval:
  """A reviewer's decision bound to one layout level.

  An approval is only valid for a level whose current layout digest, key
  configuration digest, substitution parameters, expiration and ordered
  inspection entries match the values recorded here.
  """

  level_id = attr.ib(type=str)
  approved = attr.ib(type=bool)
  layout_digest = attr.ib(type=str)
  key_config_digest = attr.ib(type=str)
  substitution_parameters = attr.ib(type=Optional[dict])
  expires = attr.ib(type=str)
  inspection_digest = attr.ib(type=str)

  def to_dict(self):
    return {
        "level_id": self.level_id,
        "approved": self.approved,
        "layout_digest": self.layout_digest,
        "key_config_digest": self.key_config_digest,
        "substitution_parameters": (
            dict(self.substitution_parameters)
            if self.substitution_parameters is not None
            else None
        ),
        "expires": self.expires,
        "inspection_digest": self.inspection_digest,
    }


# An admission callback receives the plan of a single level and returns
# ``True`` to approve or ``False`` to reject. Callbacks run locally; there is
# no separate approval service.
AdmissionCallback = Callable[[LayoutLevelPlan], bool]


def approve_plan(plan, callback):
  """Run a local admission callback for every level and return approvals.

  The callback is invoked once per layout level, including sublayout levels,
  so a top-level decision never implicitly authorizes sublayout inspections.

  Arguments:
    plan: The :class:`InspectionPlan` under review.
    callback: A callable taking a :class:`LayoutLevelPlan` and returning a
        boolean approval decision.

  Returns:
    A dictionary mapping level id to :class:`Approval`.
  """
  approvals = {}
  for level in plan.levels:
    decision = bool(callback(level))
    approvals[level.level_id] = Approval(
        level_id=level.level_id,
        approved=decision,
        layout_digest=level.layout_digest,
        key_config_digest=level.key_config_digest,
        substitution_parameters=level.substitution_parameters,
        expires=level.expires,
        inspection_digest=_digest(
            [entry.to_dict() for entry in level.inspections]
        ),
    )
  return approvals


def auto_approve(_level):
  """Admission callback that approves every level (for demos/tests)."""
  return True


def auto_deny(_level):
  """Admission callback that rejects every level (for demos/tests)."""
  return False


class InspectionExecutor:
  """Interface for running an approved inspection command.

  Implementations receive the command strictly as an argument array together
  with the approved working directory constraint and must return the
  resulting :class:`Link`.
  """

  def run_inspection(self, name, run, workdir, timeout):
    raise NotImplementedError  # pragma: no cover


class RealInspectionExecutor(InspectionExecutor):
  """Executor that records artifacts and runs the command via ``runlib``.

  It mirrors ``verifylib.run_all_inspections`` but runs a single inspection at
  a time, inside the approved working directory, and never persists links on
  its own.
  """

  def run_inspection(self, name, run, workdir, timeout):
    material_list = product_list = ["."]
    previous_cwd = os.getcwd()
    try:
      os.chdir(workdir)
      link_metadata = in_toto.runlib.in_toto_run(
          name,
          material_list,
          product_list,
          run,
          timeout=timeout,
      )
    finally:
      os.chdir(previous_cwd)
    return link_metadata.signed


class FakeInspectionExecutor(InspectionExecutor):
  """Deterministic test/demo executor that never spawns a subprocess.

  Every invocation is counted and the exact argument array and workdir are
  recorded. Returned links carry caller-provided products so that artifact
  rule verification can be exercised end to end without touching the disk.
  """

  def __init__(self, link_products=None, link_materials=None):
    # Maps inspection name to artifact hash dictionaries.
    self._link_products = link_products or {}
    self._link_materials = link_materials or {}
    self.calls = []

  @property
  def call_count(self):
    return len(self.calls)

  def run_inspection(self, name, run, workdir, timeout):
    if not isinstance(run, list) or not all(
        isinstance(arg, str) for arg in run
    ):
      raise TypeError("inspection commands must be string arrays")
    self.calls.append({"name": name, "run": list(run), "workdir": workdir})
    return Link(
        name=name,
        command=list(run),
        materials=copy.deepcopy(self._link_materials.get(name, {})),
        products=copy.deepcopy(self._link_products.get(name, {})),
        byproducts={"stdout": "", "stderr": "", "return-value": 0},
    )


def _entries_for_layout(layout):
  """Build ordered, substituted inspection entries from a layout payload."""
  entries = []
  for inspection in layout.inspect:
    entries.append(
        InspectionPlanEntry(
            name=inspection.name,
            run=list(inspection.run),
            expected_materials=[
                list(rule) for rule in inspection.expected_materials
            ],
            expected_products=[
                list(rule) for rule in inspection.expected_products
            ],
        )
    )
  return entries


def _build_level(
    level_id,
    metadata,
    layout_key_dict,
    substitution_parameters,
    workdir,
):
  """Verify trust preconditions and describe one layout level.

  Raises on bad signatures, expiration or failed parameter substitution. On
  success the passed metadata's layout payload has parameters substituted.

  Returns a tuple of the :class:`LayoutLevelPlan` and a JSON-serializable
  snapshot of the metadata *before* substitution (the signed bytes).
  """
  # Signatures must verify against the trusted key configuration.
  in_toto.verifylib.verify_metadata_signatures(metadata, layout_key_dict)
  layout = metadata.get_payload()

  # Plans are only produced for unexpired layouts.
  in_toto.verifylib.verify_layout_expiration(layout)

  # Bind the raw, pre-substitution signed bytes and keep a pristine snapshot
  # so execution can re-load and re-verify the exact signed layout.
  layout_digest = _raw_layout_digest(metadata)
  metadata_snapshot = copy.deepcopy(metadata.to_dict())
  key_digest = _key_config_digest(layout_key_dict)

  # Parameter substitution must succeed or no plan is produced. This mutates
  # the in-memory layout only; the signed bytes above are already captured.
  if substitution_parameters is not None:
    in_toto.verifylib.substitute_parameters(
        layout, substitution_parameters
    )

  level = LayoutLevelPlan(
      level_id=level_id,
      layout_digest=layout_digest,
      key_config_digest=key_digest,
      substitution_parameters=(
          dict(substitution_parameters)
          if substitution_parameters is not None
          else None
      ),
      expires=layout.expires,
      workdir=os.path.realpath(workdir),
      inspections=_entries_for_layout(layout),
  )
  return level, metadata_snapshot


def _load_sublayout_levels(
    layout,
    steps_metadata,
    super_link_dir,
    substitution_parameters,
    levels,
    snapshots,
):
  """Recursively expand sublayouts, planning and trust-checking each one.

  Normal step links are ignored here. Every sublayout becomes its own plan
  level with its own working directory (the namespaced sublayout link
  directory) and requires its own approval.
  """
  for step in layout.steps:
    for keyid, metadata in steps_metadata.get(step.name, {}).items():
      payload = metadata.get_payload()
      if payload.type_ != "layout":
        continue

      level_id = in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
          name=step.name, keyid=keyid
      )
      sub_workdir = os.path.join(super_link_dir, level_id)

      # The functionary key recorded in the superlayout is trusted for this
      # sublayout, mirroring verifylib.verify_sublayouts.
      sub_key_dict = {keyid: layout.keys.get(keyid)}

      sub_level, sub_snapshot = _build_level(
          level_id,
          metadata,
          sub_key_dict,
          substitution_parameters,
          sub_workdir,
      )
      levels.append(sub_level)
      snapshots[level_id] = sub_snapshot

      # Continue expanding nested sublayouts.
      sub_steps_metadata = in_toto.verifylib.load_links_for_layout(
          payload, sub_workdir
      )
      sub_steps_metadata = (
          in_toto.verifylib.verify_link_signature_thresholds(
              payload, sub_steps_metadata
          )
      )
      _load_sublayout_levels(
          payload,
          sub_steps_metadata,
          sub_workdir,
          substitution_parameters,
          levels,
          snapshots,
      )


class InspectionPlan:
  """The reviewable, executable result of the preparation phase."""

  def __init__(self, metadata_snapshots, layout_key_dict, levels):
    # JSON snapshots of the pre-substitution, signed metadata for every level
    # (keyed by level id) keep the plan self-contained. Execution re-loads
    # them via from_dict, rebuilding securesystemslib key/signature objects
    # from scratch and re-verifying signatures.
    self._metadata_snapshots = metadata_snapshots
    self._layout_key_dict = copy.deepcopy(layout_key_dict)
    self.levels = list(levels)

  def _fresh_metadata(self, level_id=""):
    return Metadata.from_dict(
        copy.deepcopy(self._metadata_snapshots[level_id])
    )

  def to_dict(self):
    return {"levels": [level.to_dict() for level in self.levels]}

  def to_json(self, **kwargs):
    return json.dumps(self.to_dict(), sort_keys=True, **kwargs)

  @property
  def total_inspection_count(self):
    return sum(len(level.inspections) for level in self.levels)


def prepare_inspection_plan(
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
):
  """Phase 1: produce a reviewable inspection plan without running commands.

  Performs all read-only verification preconditions (layout signatures,
  expiration, parameter substitution, link loading and threshold checks and
  sublayout expansion) and returns an :class:`InspectionPlan` describing every
  inspection across the layout hierarchy. This function never executes
  inspection commands.

  Arguments:
    metadata: A Metadata object containing the signed Layout to verify.
    layout_key_dict: Trusted public key dictionary for the top-level layout.
    link_dir_path: Directory containing link metadata and sublayout dirs.
    substitution_parameters: Optional dictionary of substitution values.

  Raises:
    SignatureVerificationError: A layout signature does not verify.
    LayoutExpiredError: A layout in the hierarchy is expired.
    KeyError: Parameter substitution cannot be completed.
    LinkNotFoundError, ThresholdVerificationError: Link checks fail.

  Returns:
    InspectionPlan
  """
  metadata = copy.deepcopy(metadata)
  workdir = os.path.realpath(link_dir_path)

  root_level, root_snapshot = _build_level(
      "",
      metadata,
      layout_key_dict,
      substitution_parameters,
      workdir,
  )
  levels = [root_level]
  snapshots = {"": root_snapshot}

  layout = metadata.get_payload()
  steps_metadata = in_toto.verifylib.load_links_for_layout(layout, workdir)
  steps_metadata = in_toto.verifylib.verify_link_signature_thresholds(
      layout, steps_metadata
  )
  _load_sublayout_levels(
      layout,
      steps_metadata,
      workdir,
      substitution_parameters,
      levels,
      snapshots,
  )

  return InspectionPlan(snapshots, layout_key_dict, levels)


def _verify_approval(level, approval):
  """Re-check every binding of an approval against the current level."""
  if approval is None or not approval.approved:
    raise ApprovalError(
        f"Layout level '{level.level_id or '<root>'}' was not approved."
    )

  if approval.level_id != level.level_id:
    raise ApprovalError(
        f"Approval is bound to level '{approval.level_id}', not"
        f" '{level.level_id}'."
    )

  if approval.layout_digest != level.layout_digest:
    raise ApprovalError(
        "Layout bytes changed after approval; the approval is stale."
    )

  if approval.key_config_digest != level.key_config_digest:
    raise ApprovalError(
        "Trusted key configuration changed after approval;"
        " the approval is stale."
    )

  if approval.substitution_parameters != level.substitution_parameters:
    raise ApprovalError(
        "Substitution parameters changed after approval;"
        " the approval is stale."
    )

  if approval.expires != level.expires:
    raise ApprovalError(
        "Layout expiration changed after approval; the approval is stale."
    )

  current_inspection_digest = _digest(
      [entry.to_dict() for entry in level.inspections]
  )
  if approval.inspection_digest != current_inspection_digest:
    raise ApprovalError(
        "Inspection commands or artifact rules changed after approval;"
        " the approval is stale."
    )


def _execute_level(
    level,
    metadata,
    layout_key_dict,
    steps_metadata,
    link_dir_path,
    approvals,
    executor,
    timeout,
    substitution_parameters,
    snapshots,
):
  """Execute one approved layout level and recurse into its sublayouts.

  Returns the reduced chain link dictionary (links keyed by item name) for
  this level, including summary links for sublayouts.
  """
  approval = approvals.get(level.level_id)
  _verify_approval(level, approval)

  # Re-check expiration at execution time, not just at planning time.
  layout = metadata.get_payload()
  in_toto.verifylib.verify_layout_expiration(layout)

  # Step rules are verified before any inspection command can run.
  chain_link_dict = _verify_sublayouts_for_execution(
      layout,
      steps_metadata,
      link_dir_path,
      approvals,
      executor,
      timeout,
      substitution_parameters,
      snapshots,
  )
  in_toto.verifylib.verify_all_steps_command_alignment(
      layout, chain_link_dict
  )
  in_toto.verifylib.verify_threshold_constraints(
      layout, chain_link_dict
  )
  reduced_chain_link_dict = in_toto.verifylib.reduce_chain_links(
      chain_link_dict
  )
  in_toto.verifylib.verify_all_item_rules(
      layout.steps, reduced_chain_link_dict
  )

  inspection_links = {}
  for entry in level.inspections:
    link = executor.run_inspection(
        entry.name, list(entry.run), level.workdir, timeout
    )
    in_toto.verifylib._raise_on_bad_retval(  # noqa: SLF001
        link.byproducts.get("return-value"), entry.run
    )
    inspection_links[entry.name] = link

  combined_links = reduced_chain_link_dict.copy()
  combined_links.update(inspection_links)
  in_toto.verifylib.verify_all_item_rules(layout.inspect, combined_links)

  return reduced_chain_link_dict


def _verify_sublayouts_for_execution(
    layout,
    steps_metadata,
    link_dir_path,
    approvals,
    executor,
    timeout,
    substitution_parameters,
    snapshots,
):
  """Replacement for verifylib.verify_sublayouts that enforces approvals."""
  chain_link_dict = {}
  for step in layout.steps:
    key_link_dict = {}
    for keyid, metadata in steps_metadata.get(step.name, {}).items():
      payload = metadata.get_payload()
      if payload.type_ == "layout":
        level_id = in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=step.name, keyid=keyid
        )
        sub_workdir = os.path.join(link_dir_path, level_id)
        sub_key_dict = {keyid: layout.keys.get(keyid)}

        # Re-load the exact signed sublayout bytes captured at planning time
        # and re-derive its level, so every binding is re-checked rather than
        # trusted from planning time.
        sub_metadata = Metadata.from_dict(
            copy.deepcopy(snapshots[level_id])
        )
        sub_level, _ = _build_level(
            level_id,
            sub_metadata,
            sub_key_dict,
            substitution_parameters,
            sub_workdir,
        )
        sub_payload = sub_metadata.get_payload()
        sub_steps_metadata = in_toto.verifylib.load_links_for_layout(
            sub_payload, sub_workdir
        )
        sub_steps_metadata = (
            in_toto.verifylib.verify_link_signature_thresholds(
                sub_payload, sub_steps_metadata
            )
        )
        sub_reduced = _execute_level(
            sub_level,
            sub_metadata,
            sub_key_dict,
            sub_steps_metadata,
            sub_workdir,
            approvals,
            executor,
            timeout,
            substitution_parameters,
            snapshots,
        )
        payload = in_toto.verifylib.get_summary_link(
            sub_payload, sub_reduced, step.name
        )

      key_link_dict[keyid] = payload
    chain_link_dict[step.name] = key_link_dict
  return chain_link_dict


def execute_inspection_plan(
    plan,
    approvals,
    executor,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
  """Phase 2: execute an approved plan.

  Re-derives every layout level from the plan's signed metadata, re-checks
  all approval bindings and expiration, and only then runs inspections via
  ``executor``. Rejected or stale approvals raise :class:`ApprovalError`
  before any command runs.

  Arguments:
    plan: The :class:`InspectionPlan` from the preparation phase.
    approvals: Level-id keyed approvals from :func:`approve_plan`.
    executor: An :class:`InspectionExecutor`.
    timeout: Per-command timeout in seconds.

  Raises:
    ApprovalError: A level is unapproved, rejected or has stale bindings.
    LayoutExpiredError: A layout expired between planning and execution.
    BadReturnValueError, RuleVerificationError: Normal verification failures.

  Returns:
    A summary :class:`Link` of the verified top-level supply chain.
  """
  if not isinstance(executor, InspectionExecutor):
    raise TypeError("executor must implement InspectionExecutor")

  layout_key_dict = copy.deepcopy(plan._layout_key_dict)  # noqa: SLF001
  params = plan.levels[0].substitution_parameters

  # Re-load the exact signed root bytes captured at planning time and re-run
  # signature, expiration and substitution checks. Approvals are compared
  # against these fresh bindings.
  metadata = plan._fresh_metadata("")  # noqa: SLF001
  root_level, _ = _build_level(
      "",
      metadata,
      layout_key_dict,
      params,
      plan.levels[0].workdir,
  )

  # The freshly derived hierarchy must match the hierarchy that was reviewed.
  fresh_levels = [root_level]
  layout = metadata.get_payload()
  steps_metadata = in_toto.verifylib.load_links_for_layout(
      layout, root_level.workdir
  )
  steps_metadata = in_toto.verifylib.verify_link_signature_thresholds(
      layout, steps_metadata
  )
  _load_sublayout_levels(
      layout,
      steps_metadata,
      root_level.workdir,
      params,
      fresh_levels,
      {},
  )

  reviewed_ids = [level.level_id for level in plan.levels]
  fresh_ids = [level.level_id for level in fresh_levels]
  if reviewed_ids != fresh_ids:
    raise ApprovalError(
        "Layout hierarchy changed after approval (new or removed sublayout"
        " checks); the approval is stale."
    )

  reduced = _execute_level(
      root_level,
      metadata,
      layout_key_dict,
      steps_metadata,
      root_level.workdir,
      approvals,
      executor,
      timeout,
      params,
      plan._metadata_snapshots,  # noqa: SLF001
  )

  return in_toto.verifylib.get_summary_link(layout, reduced, "")
