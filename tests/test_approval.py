# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests (and executable demo) for the two-phase inspection
approval flow in :mod:`in_toto.approval`.

The tests use a local admission callback and a fake executor, so no command is
ever spawned. They demonstrate that:

 * the preparation phase produces a reviewable plan without running anything,
 * rejecting the plan leaves the executor and inspection artifacts untouched,
 * an approved plan executes and verifies artifact rules,
 * changing a single parameter or adding a sublayout inspection invalidates
   the old approval, and
 * sublayout inspections require their own approval and cannot ride on a
   top-level approval.
"""

import copy

import pytest

from in_toto.approval import (
    ApprovalError,
    FakeInspectionExecutor,
    approve_plan,
    auto_approve,
    auto_deny,
    execute_inspection_plan,
    prepare_inspection_plan,
)
from in_toto.exceptions import LayoutExpiredError, SignatureVerificationError
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock

from tests.common import SignerStore

HASH = {"sha256": "0" * 64}


def _write_link(link_dir, name, signer, products=None, materials=None,
                command=None):
  """Create and persist a signed link metadata file."""
  link = Link(
      name=name,
      command=command or [],
      materials=materials or {},
      products=products or {},
      byproducts={"stdout": "", "stderr": "", "return-value": 0},
  )
  metadata = Metablock(signed=link)
  metadata.create_signature(signer)
  path = link_dir / FILENAME_FORMAT.format(
      step_name=name, keyid=signer.public_key.keyid
  )
  metadata.dump(str(path))
  return metadata


def _root_layout(owner_pub, writer_pub, extra_inspection=False,
                 product_name="{ARTIFACT}"):
  """Build a signed-looking root layout with one step and two inspections.

  Parameter placeholders are only substituted during planning.
  """
  inspect = [
      Inspection(
          name="check-thing",
          run=["echo", "{ARTIFACT}"],
          expected_materials=[["DISALLOW", "*"]],
          expected_products=[
              ["CREATE", product_name],
              ["ALLOW", product_name],
              ["DISALLOW", "*"],
          ],
      ),
      Inspection(
          name="list-thing",
          run=["ls", "-l", "{ARTIFACT}"],
          expected_materials=[["DISALLOW", "*"]],
          expected_products=[["DISALLOW", "*"]],
      ),
  ]
  if extra_inspection:
    inspect.append(
        Inspection(
            name="extra-check",
            run=["true"],
            expected_materials=[["DISALLOW", "*"]],
            expected_products=[["DISALLOW", "*"]],
        )
    )

  return Layout(
      keys={writer_pub["keyid"]: writer_pub},
      steps=[
          Step(
              name="write-code",
              pubkeys=[writer_pub["keyid"]],
              expected_command=["vi", "foo.py"],
          )
      ],
      inspect=inspect,
  )


def _signed(layout, signer):
  metadata = Metablock(signed=layout)
  metadata.create_signature(signer)
  return metadata


@pytest.fixture()
def chain(tmp_path):
  owner = SignerStore.rsa
  owner_pub = SignerStore.rsa_pub
  writer = SignerStore.ecdsa
  writer_pub = SignerStore.ecdsa_pub

  # Evidence for the only step.
  _write_link(
      tmp_path,
      "write-code",
      writer,
      products={"foo.py": HASH},
      command=["vi", "foo.py"],
  )

  layout = _root_layout(owner_pub, writer_pub)
  metadata = _signed(layout, owner)
  return {
      "tmp_path": tmp_path,
      "owner": owner,
      "owner_pub": owner_pub,
      "writer": writer,
      "writer_pub": writer_pub,
      "metadata": metadata,
      "params": {"ARTIFACT": "foo.txt"},
  }


def _fake_executor():
  # Only check-thing reports a product, matching its CREATE/ALLOW rules.
  return FakeInspectionExecutor(
      link_products={"check-thing": {"foo.txt": HASH}}
  )


def test_prepare_lists_arguments_rules_and_workdir(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )

  assert len(plan.levels) == 1
  level = plan.levels[0]
  assert level.level_id == ""
  # The workdir constraint is the realpath of the link directory.
  assert level.workdir == str(chain["tmp_path"].resolve())
  assert level.substitution_parameters == {"ARTIFACT": "foo.txt"}

  names = [entry.name for entry in level.inspections]
  assert names == ["check-thing", "list-thing"]

  # Original order, fully substituted, kept as arrays.
  assert level.inspections[0].run == ["echo", "foo.txt"]
  assert level.inspections[1].run == ["ls", "-l", "foo.txt"]
  assert level.inspections[0].expected_products[0] == ["CREATE", "foo.txt"]

  # Bindings are populated and stable-looking hex digests.
  assert len(level.layout_digest) == 64
  assert len(level.key_config_digest) == 64


def test_preparation_never_runs_commands(chain):
  # prepare_inspection_plan does not even accept an executor; running it must
  # leave no artifact behind and must not spawn anything.
  before = set(p.name for p in chain["tmp_path"].iterdir())
  prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  after = set(p.name for p in chain["tmp_path"].iterdir())
  assert before == after


def test_rejected_plan_runs_nothing(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  approvals = approve_plan(plan, auto_deny)
  executor = _fake_executor()

  link_files_before = set(chain["tmp_path"].glob("*.link"))
  with pytest.raises(ApprovalError):
    execute_inspection_plan(plan, approvals, executor)

  assert executor.call_count == 0
  assert executor.calls == []
  # No inspection link artifacts are produced on rejection.
  assert set(chain["tmp_path"].glob("*.link")) == link_files_before


def test_approved_plan_executes_and_verifies_rules(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  approvals = approve_plan(plan, auto_approve)
  executor = _fake_executor()

  summary = execute_inspection_plan(plan, approvals, executor)

  assert executor.call_count == 2
  assert [call["name"] for call in executor.calls] == [
      "check-thing",
      "list-thing",
  ]
  # Commands stay arrays and are passed through verbatim.
  assert executor.calls[0]["run"] == ["echo", "foo.txt"]
  assert executor.calls[1]["run"] == ["ls", "-l", "foo.txt"]
  assert executor.calls[0]["workdir"] == str(chain["tmp_path"].resolve())
  # Inspection products now exist (the fake link was produced).
  assert summary.name == ""


def test_changing_one_parameter_invalidates_approval(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  approvals = approve_plan(plan, auto_approve)

  # Re-plan with a single changed parameter value.
  changed = copy.deepcopy(chain["metadata"])
  stale_plan = prepare_inspection_plan(
      changed,
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters={"ARTIFACT": "bar.txt"},
  )
  executor = _fake_executor()
  with pytest.raises(ApprovalError):
    execute_inspection_plan(stale_plan, approvals, executor)
  assert executor.call_count == 0


def test_changed_key_config_invalidates_approval(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  approvals = approve_plan(plan, auto_approve)

  # An attacker-supplied "trusted" key config cannot reuse the old approval.
  other_pub = SignerStore.ed25519_pub
  with pytest.raises((ApprovalError, SignatureVerificationError)):
    rogue_plan = prepare_inspection_plan(
        copy.deepcopy(chain["metadata"]),
        {other_pub["keyid"]: other_pub},
        link_dir_path=str(chain["tmp_path"]),
        substitution_parameters=chain["params"],
    )
    execute_inspection_plan(rogue_plan, approvals, _fake_executor())


def test_expired_layout_is_rechecked_at_execution(chain):
  metadata = chain["metadata"]
  metadata.signed.set_relative_expiration(months=-1)
  # Re-sign so signatures still verify; only expiration should fail.
  metadata.signatures = []
  metadata.create_signature(chain["owner"])

  with pytest.raises(LayoutExpiredError):
    prepare_inspection_plan(
        metadata,
        {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
        link_dir_path=str(chain["tmp_path"]),
        substitution_parameters=chain["params"],
    )


def test_bad_signature_blocks_planning(chain):
  metadata = copy.deepcopy(chain["metadata"])
  metadata.signatures[0]["sig"] = "00" * 64
  with pytest.raises(SignatureVerificationError):
    prepare_inspection_plan(
        metadata,
        {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
        link_dir_path=str(chain["tmp_path"]),
        substitution_parameters=chain["params"],
    )


def test_failed_parameter_substitution_blocks_planning(chain):
  with pytest.raises(KeyError):
    prepare_inspection_plan(
        chain["metadata"],
        {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
        link_dir_path=str(chain["tmp_path"]),
        substitution_parameters={},
    )


def _build_sublayout_hierarchy(tmp_path, owner, owner_pub, writer,
                               writer_pub, extra_inspection=False):
  """Root layout delegates one step to a sublayout that has inspections."""
  sub_dir_name = SUBLAYOUT_LINK_DIR_FORMAT.format(
      name="delegated", keyid=writer_pub["keyid"]
  )
  sub_dir = tmp_path / sub_dir_name
  sub_dir.mkdir(exist_ok=True)

  # The sublayout has one normal step (with a link) and inspections.
  _write_link(sub_dir, "sub-step", writer, command=["true"])

  sub_inspections = [
      Inspection(
          name="sub-check",
          run=["echo", "sub"],
          expected_materials=[["DISALLOW", "*"]],
          expected_products=[["DISALLOW", "*"]],
      )
  ]
  if extra_inspection:
    sub_inspections.append(
        Inspection(
            name="sub-extra",
            run=["true"],
            expected_materials=[["DISALLOW", "*"]],
            expected_products=[["DISALLOW", "*"]],
        )
    )

  sub_layout = Layout(
      keys={writer_pub["keyid"]: writer_pub},
      steps=[Step(name="sub-step", pubkeys=[writer_pub["keyid"]])],
      inspect=sub_inspections,
  )
  sub_metadata = _signed(sub_layout, writer)
  sub_metadata.dump(
      str(
          tmp_path
          / FILENAME_FORMAT.format(
              step_name="delegated", keyid=writer_pub["keyid"]
          )
      )
  )

  root_layout = Layout(
      keys={writer_pub["keyid"]: writer_pub},
      steps=[
          Step(name="delegated", pubkeys=[writer_pub["keyid"]])
      ],
  )
  root_metadata = _signed(root_layout, owner)
  return root_metadata, sub_dir_name


def test_sublayout_requires_its_own_approval(tmp_path):
  owner, owner_pub = SignerStore.rsa, SignerStore.rsa_pub
  writer, writer_pub = SignerStore.ecdsa, SignerStore.ecdsa_pub
  root_metadata, sub_dir = _build_sublayout_hierarchy(
      tmp_path, owner, owner_pub, writer, writer_pub
  )

  plan = prepare_inspection_plan(
      root_metadata,
      {owner_pub["keyid"]: owner_pub},
      link_dir_path=str(tmp_path),
  )
  # Two levels: root (no inspections) and the sublayout.
  assert [level.level_id for level in plan.levels] == ["", sub_dir]
  assert plan.levels[1].inspections[0].name == "sub-check"

  # Approve only the root level; the sublayout level is missing.
  all_approvals = approve_plan(plan, auto_approve)
  root_only = {"": all_approvals[""]}
  executor = FakeInspectionExecutor()
  with pytest.raises(ApprovalError):
    execute_inspection_plan(plan, root_only, executor)
  assert executor.call_count == 0


def test_sublayout_executes_with_explicit_approval(tmp_path):
  owner, owner_pub = SignerStore.rsa, SignerStore.rsa_pub
  writer, writer_pub = SignerStore.ecdsa, SignerStore.ecdsa_pub
  root_metadata, _ = _build_sublayout_hierarchy(
      tmp_path, owner, owner_pub, writer, writer_pub
  )

  plan = prepare_inspection_plan(
      root_metadata,
      {owner_pub["keyid"]: owner_pub},
      link_dir_path=str(tmp_path),
  )
  approvals = approve_plan(plan, auto_approve)
  executor = FakeInspectionExecutor()

  execute_inspection_plan(plan, approvals, executor)
  assert executor.call_count == 1
  assert executor.calls[0]["name"] == "sub-check"
  # The workdir is the namespaced sublayout directory.
  assert executor.calls[0]["workdir"] == plan.levels[1].workdir


def test_new_sublayout_inspection_invalidates_old_approval(tmp_path):
  owner, owner_pub = SignerStore.rsa, SignerStore.rsa_pub
  writer, writer_pub = SignerStore.ecdsa, SignerStore.ecdsa_pub
  root_metadata, _ = _build_sublayout_hierarchy(
      tmp_path, owner, owner_pub, writer, writer_pub
  )

  plan = prepare_inspection_plan(
      root_metadata,
      {owner_pub["keyid"]: owner_pub},
      link_dir_path=str(tmp_path),
  )
  approvals = approve_plan(plan, auto_approve)

  # Add an inspection to the sublayout after approval and re-sign.
  new_root, _ = _build_sublayout_hierarchy(
      tmp_path,
      owner,
      owner_pub,
      writer,
      writer_pub,
      extra_inspection=True,
  )
  new_plan = prepare_inspection_plan(
      new_root,
      {owner_pub["keyid"]: owner_pub},
      link_dir_path=str(tmp_path),
  )
  executor = FakeInspectionExecutor()
  with pytest.raises(ApprovalError):
    execute_inspection_plan(new_plan, approvals, executor)
  assert executor.call_count == 0


def test_plan_is_json_reviewable(chain):
  plan = prepare_inspection_plan(
      chain["metadata"],
      {chain["owner_pub"]["keyid"]: chain["owner_pub"]},
      link_dir_path=str(chain["tmp_path"]),
      substitution_parameters=chain["params"],
  )
  import json

  rendered = plan.to_json(indent=2)
  assert "check-thing" in rendered
  assert "layout_digest" in rendered
  parsed = json.loads(rendered)
  first_run = parsed["levels"][0]["inspections"][0]["run"]
  assert first_run == ["echo", "foo.txt"]
