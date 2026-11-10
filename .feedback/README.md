# Feedback task starting environment

Upstream: https://github.com/in-toto/in-toto
Upstream commit: `e352b43ad7cb8915d84c36d791aa61346152a0a3`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_rulelib.py tests/test_param_substitution.py tests/test_verifylib.py tests/test_resolver.py -k 'not gpg and not test_verify_disallow_rule and not test_verify_require_rule'
```

Scope note: Offline focused suite excludes optional GPG and two upstream direct-rule tests that fail because module-global RULE_TRACE lacks source_type/source_name when run without prior verifier initialization. Failure logs preserved; no source patch or claim of full-suite success.

Observed baseline (2026-11-10): `71 passed, 10 deselected, 180 warnings in 0.78s`
Whole-command wall time: 0.956 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
