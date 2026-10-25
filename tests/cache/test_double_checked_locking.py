"""The branch where another thread wins the race to build the singleton.

All four singletons check `_instance is None`, take the lock, then check
again.
The second check exists for one interleaving: two threads pass the first
check, one builds the instance, and the other must find it rather than build
a second. That is only reachable under a real race, so the race is staged.

Worth testing rather than ignoring. Without the second check, the losing
thread would build its own store and every write it made would land in an
object nothing else could see.
"""

from __future__ import annotations

import pytest

from secretref import CommandPolicy, EnvironmentPolicy, FilePolicy, ResolutionCache


class RaceLock:
    """A lock that lets another thread finish first.

    Builds the instance during acquisition, so by the time the caller holds
    the lock the second check has something to find. That reproduces the
    interleaving without depending on the scheduler.
    """

    def __init__(self, owner: type, built: object) -> None:
        self._owner = owner
        self._built = built

    def __enter__(self) -> RaceLock:
        self._owner._instance = self._built
        return self

    def __exit__(self, *_: object) -> None:
        return None


class TestDoubleCheckedLocking:
    @pytest.mark.parametrize(
        "singleton", [ResolutionCache, CommandPolicy, FilePolicy, EnvironmentPolicy]
    )
    def test_the_loser_of_the_race_gets_the_winner_s_instance(self, singleton, monkeypatch):
        monkeypatch.setattr(singleton, "_instance", None)
        winner = object.__new__(singleton)
        winner._initialize()
        monkeypatch.setattr(singleton, "_singleton_lock", RaceLock(singleton, winner))

        assert singleton() is winner

    @pytest.mark.parametrize(
        "singleton", [ResolutionCache, CommandPolicy, FilePolicy, EnvironmentPolicy]
    )
    def test_it_builds_one_when_it_wins(self, singleton, monkeypatch):
        monkeypatch.setattr(singleton, "_instance", None)
        first = singleton()
        assert singleton() is first
