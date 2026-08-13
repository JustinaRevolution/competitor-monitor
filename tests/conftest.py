"""
Makes the `check(...)` tallies in these test modules mean something under pytest.

Every test file here is written to run two ways: as a script
(`python3 tests/test_round9.py`), where the `__main__` block reads the module's
`FAIL` list and exits non-zero; and under pytest, which knows nothing about that
list. A `check()` that records a failure raises nothing, so under pytest a test
function that failed every single one of its assertions still returned normally
and was reported as passing — the suite was green no matter what the app did.
Proven by deleting CSRF verification outright and watching pytest still report
all green.

The hook below closes that gap in one place: any new entries a test adds to its
module's `FAIL` list are raised as an assertion failure at the end of that test's
call phase. Nothing in the test files changes, and the script entry points keep
working exactly as before (pytest is the only thing that loads this file).

The check runs in the *call* phase, not in a fixture teardown, so a suite with
failed checks reports "failed" against the named test rather than a passing test
plus a teardown error.
"""

import pytest


@pytest.hookimpl(wrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    """Fail the test if it recorded any failed `check()` in its module's FAIL list."""
    failures = getattr(pyfuncitem.module, "FAIL", None)
    before = len(failures) if isinstance(failures, list) else None

    result = yield  # a real exception from the test propagates from here

    if before is not None:
        new_failures = pyfuncitem.module.FAIL[before:]
        assert not new_failures, (
            f"{len(new_failures)} failed check(s): " + "; ".join(map(str, new_failures))
        )
    return result
