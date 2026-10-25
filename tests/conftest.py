"""Fixtures shared by every test in this package."""

from __future__ import annotations

import pytest

from secretref import CommandPolicy, EnvironmentPolicy, FilePolicy, ResolutionCache


@pytest.fixture(autouse=True)
def isolated_process_state():
    """Reset the two singletons around every test.

    All four are process-wide by design, which is what makes them useful and
    what would otherwise let one test see another's configuration. The reset
    is automatic so a test cannot forget it.

    FilePolicy resets to its *default* rather than to anything-goes, so the
    suite exercises what a caller actually gets. A test needing a file
    outside the standard mounts says so, the way a deployment would.
    """
    CommandPolicy().forbid()
    FilePolicy().reset()
    EnvironmentPolicy().relax()
    ResolutionCache().disable()
    yield
    CommandPolicy().forbid()
    FilePolicy().reset()
    EnvironmentPolicy().relax()
    ResolutionCache().disable()


@pytest.fixture
def commands_allowed():
    """Permit the shell utilities the command tests use.

    Named explicitly rather than allowing everything, so the tests exercise
    the allowlist the way a deployment would.
    """
    CommandPolicy().allow("echo", "sh", "op", "printenv", "head", "id", "pwd")
    yield CommandPolicy()
    CommandPolicy().forbid()


@pytest.fixture
def files_anywhere():
    """Permit file references outside the standard secret mounts.

    What a laptop or a test needs, and what a container should not have.
    Requested explicitly so the suite shows which tests depend on it.
    """
    FilePolicy().allow_anywhere()
    yield FilePolicy()
    FilePolicy().reset()
