# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""End-to-end demonstration of the two-phase inspection approval flow.

Run from the repository root:

    .venv/bin/python examples/approval_demo.py

The demo uses a *local* admission callback (no approval service) and a fake
executor (no subprocess is ever spawned). It walks through:

  1. preparing an inspection plan (no command runs),
  2. rejecting the plan -> zero executor calls and zero inspection products,
  3. approving the plan -> the inspections execute and rules verify, and
  4. changing one parameter and adding a sublayout inspection -> the old
     approval is rejected as stale.
"""

import copy
import logging
import tempfile
from pathlib import Path

from in_toto.approval import (
    ApprovalError,
    FakeInspectionExecutor,
    approve_plan,
    auto_approve,
    auto_deny,
    execute_inspection_plan,
    prepare_inspection_plan,
)
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


def write_link(directory, name, signer):
  link = Link(
      name=name,
      command=["vi", "foo.py"],
      products={"foo.py": HASH},
      byproducts={"stdout": "", "stderr": "", "return-value": 0},
  )
  metadata = Metablock(signed=link)
  metadata.create_signature(signer)
  metadata.dump(
      str(directory / FILENAME_FORMAT.format(
          step_name=name, keyid=signer.public_key.keyid
      ))
  )


def build_root_layout(writer_pub):
  return Layout(
      keys={writer_pub["keyid"]: writer_pub},
      steps=[Step(name="write-code", pubkeys=[writer_pub["keyid"]])],
      inspect=[
          Inspection(
              name="check-thing",
              run=["echo", "{ARTIFACT}"],
              expected_materials=[["DISALLOW", "*"]],
              expected_products=[
                  ["CREATE", "{ARTIFACT}"],
                  ["ALLOW", "{ARTIFACT}"],
                  ["DISALLOW", "*"],
              ],
          )
      ],
  )


def main():
  owner, owner_pub = SignerStore.rsa, SignerStore.rsa_pub
  writer, writer_pub = SignerStore.ecdsa, SignerStore.ecdsa_pub
  params = {"ARTIFACT": "foo.txt"}

  with tempfile.TemporaryDirectory() as raw_tmp:
    tmp = Path(raw_tmp)
    write_link(tmp, "write-code", writer)
    metadata = Metablock(signed=build_root_layout(writer_pub))
    metadata.create_signature(owner)
    owner_keys = {owner_pub["keyid"]: owner_pub}

    # Phase 1: prepare the plan. No executor exists yet and no command runs.
    plan = prepare_inspection_plan(
        metadata,
        owner_keys,
        link_dir_path=str(tmp),
        substitution_parameters=params,
    )
    entry = plan.levels[0].inspections[0]
    print("Planned command array:", entry.run)
    print("Working directory:    ", plan.levels[0].workdir)
    print("Product rules:        ", entry.expected_products)
    print("Layout digest:        ", plan.levels[0].layout_digest)

    # Rejected plan: nothing executes.
    denied = approve_plan(plan, auto_deny)
    denied_executor = FakeInspectionExecutor(
        link_products={"check-thing": {"foo.txt": HASH}}
    )
    try:
      execute_inspection_plan(plan, denied, denied_executor)
    except ApprovalError as error:
      print("\nRejected plan ->", error)
    print("Executor calls after rejection:", denied_executor.call_count)

    # Approved plan: the fake inspections "run" and their rules verify.
    approved = approve_plan(plan, auto_approve)
    executor = FakeInspectionExecutor(
        link_products={"check-thing": {"foo.txt": HASH}}
    )
    execute_inspection_plan(plan, approved, executor)
    print("\nApproved plan executed. Executor calls:", executor.call_count)
    print("Executed command (array form):   ", executor.calls[0]["run"])

    # A single changed parameter makes the old approval stale.
    changed_plan = prepare_inspection_plan(
        copy.deepcopy(metadata),
        owner_keys,
        link_dir_path=str(tmp),
        substitution_parameters={"ARTIFACT": "bar.txt"},
    )
    stale_executor = FakeInspectionExecutor()
    try:
      execute_inspection_plan(changed_plan, approved, stale_executor)
    except ApprovalError as error:
      print("\nChanged parameter ->", error)
    print("Executor calls after stale parameter:", stale_executor.call_count)

    # A newly added sublayout inspection also needs its own approval.
    sub_dir_name = SUBLAYOUT_LINK_DIR_FORMAT.format(
        name="delegated", keyid=writer_pub["keyid"]
    )
    (tmp / sub_dir_name).mkdir(exist_ok=True)
    sub_link = Link(
        name="sub-step",
        command=["true"],
        byproducts={"stdout": "", "stderr": "", "return-value": 0},
    )
    sub_meta = Metablock(signed=sub_link)
    sub_meta.create_signature(writer)
    sub_meta.dump(str(tmp / sub_dir_name / FILENAME_FORMAT.format(
        step_name="sub-step", keyid=writer.public_key.keyid
    )))
    sub_layout = Layout(
        keys={writer_pub["keyid"]: writer_pub},
        steps=[Step(name="sub-step", pubkeys=[writer_pub["keyid"]])],
        inspect=[
            Inspection(
                name="sub-check",
                run=["true"],
                expected_materials=[["DISALLOW", "*"]],
                expected_products=[["DISALLOW", "*"]],
            )
        ],
    )
    sub_signed = Metablock(signed=sub_layout)
    sub_signed.create_signature(writer)
    sub_signed.dump(str(tmp / FILENAME_FORMAT.format(
        step_name="delegated", keyid=writer_pub["keyid"]
    )))

    root_with_sublayout = Metablock(signed=Layout(
        keys={writer_pub["keyid"]: writer_pub},
        steps=[Step(name="delegated", pubkeys=[writer_pub["keyid"]])],
    ))
    root_with_sublayout.create_signature(owner)
    nested_plan = prepare_inspection_plan(
        root_with_sublayout, owner_keys, link_dir_path=str(tmp)
    )
    nested_executor = FakeInspectionExecutor()
    try:
      execute_inspection_plan(nested_plan, approved, nested_executor)
    except ApprovalError as error:
      print("\nNew sublayout check ->", error)
    print("Executor calls without sublayout approval:",
          nested_executor.call_count)

    # Explicitly approving every level (root + sublayout) lets it execute.
    nested_approvals = approve_plan(nested_plan, auto_approve)
    nested_approved_executor = FakeInspectionExecutor()
    execute_inspection_plan(
        nested_plan, nested_approvals, nested_approved_executor
    )
    print("Executor calls after explicit sublayout approval:",
          nested_approved_executor.call_count)
    print("Executed sublayout inspection:",
          nested_approved_executor.calls[0]["name"])


if __name__ == "__main__":
  logging.disable(logging.CRITICAL)
  main()
