"""Reconfiguring a policy must not expose a half-applied one.

A policy is read on every resolution and written when an operator configures
it. Setting several fields in sequence left a window where a reader saw a
configuration nobody asked for — and in the worst ordering, a *more*
permissive one than either the old or the new.

Each policy now keeps one frozen snapshot and swaps the whole object in a
single assignment, which is atomic in CPython. These tests pin that: a
reader sees the old settings or the new ones, never a mixture, and no lock
sits on the read path.
"""

from __future__ import annotations

import threading

import pytest

from secretref import CommandPolicy, FilePolicy
from secretref.policies.settings import (
    CommandSettings,
    EnvironmentSettings,
    FileSettings,
)


class TestSettingsAreImmutable:
    @pytest.mark.parametrize(
        "settings", [CommandSettings(), FileSettings(), EnvironmentSettings()]
    )
    def test_a_snapshot_cannot_be_mutated(self, settings):
        """So a reader holding one cannot have it changed underneath them."""
        with pytest.raises((AttributeError, TypeError)):
            settings.enabled = True  # type: ignore[misc]

    @pytest.mark.parametrize(
        "settings", [CommandSettings(), FileSettings(), EnvironmentSettings()]
    )
    def test_with_changes_returns_a_new_snapshot(self, settings):
        changed = (
            settings.with_changes(max_bytes=1)
            if hasattr(settings, "max_bytes")
            else settings.with_changes()
        )
        assert changed is not settings

    def test_the_command_default_is_the_safe_position(self):
        assert CommandSettings().enabled is False
        assert CommandSettings().allowed == frozenset()

    def test_the_file_default_is_the_secret_mounts(self):
        roots = {str(root) for root in FileSettings().roots}
        assert "/run/secrets" in roots

    def test_the_environment_default_is_unrestricted(self):
        assert EnvironmentSettings().active is False


class TestReconfigurationIsAtomic:
    def test_a_command_policy_is_never_half_applied(self):
        """An empty allowlist means "any executable", so a reader seeing
        enabled=True with the allowlist not yet set would permit more than
        either configuration did."""
        policy = CommandPolicy()
        policy.allow("op")
        observed: list[tuple[bool, tuple[str, ...]]] = []
        stop = threading.Event()

        def reconfigure() -> None:
            while not stop.is_set():
                policy.allow("op")
                policy.allow("vault")

        def observe() -> None:
            while not stop.is_set():
                settings = policy._settings
                observed.append((settings.enabled, tuple(sorted(settings.allowed))))

        writer = threading.Thread(target=reconfigure)
        reader = threading.Thread(target=observe)
        writer.start()
        reader.start()
        stop.wait(0.2)
        stop.set()
        writer.join()
        reader.join()

        # Only the two configurations that were actually set, never a mix
        # and never an empty allowlist with enabled true.
        assert set(observed) <= {(True, ("op",)), (True, ("vault",))}

    def test_a_file_policy_is_never_half_applied(self, tmp_path):
        policy = FilePolicy()
        first = tmp_path / "one"
        second = tmp_path / "two"
        first.mkdir()
        second.mkdir()
        # Put the policy in a known state before the reader starts, or it
        # legitimately observes the default — which has two roots.
        policy.restrict(first, require_private=True)
        observed: set[tuple[int, bool]] = set()
        stop = threading.Event()

        def reconfigure() -> None:
            while not stop.is_set():
                policy.restrict(first, require_private=True)
                policy.restrict(second, require_private=False)

        def observe() -> None:
            while not stop.is_set():
                settings = policy._settings
                observed.add((len(settings.roots), settings.require_private))

        writer = threading.Thread(target=reconfigure)
        reader = threading.Thread(target=observe)
        writer.start()
        reader.start()
        stop.wait(0.2)
        stop.set()
        writer.join()
        reader.join()

        assert observed <= {(1, True), (1, False)}

    def test_reads_take_no_lock(self):
        """The reason for a snapshot rather than locking: check() runs on
        every resolution, so a lock there would be contended by design."""
        source = __import__("pathlib").Path("src/secretref/policies/command.py").read_text()
        check = source[source.index("def check(") : source.index("def environment(")]
        assert "with self._lock" not in check
        assert "_singleton_lock" not in check
