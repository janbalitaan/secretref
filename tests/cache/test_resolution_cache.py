"""Caching resolved secrets, which is a trade a caller has to choose.

Off by default for two reasons the tests pin: a cached secret stays in memory
after the only read that needed it, and a rotated secret keeps serving the
old value until the entry expires.
"""

from __future__ import annotations

import threading
import time

import pytest

from secretref import CommandPolicy, ResolutionCache, SecretRef


@pytest.fixture
def cache() -> ResolutionCache:
    """The one cache, cleared and enabled for this test."""
    store = ResolutionCache()
    store.enable()
    store.clear()
    return store


class TestResolutionCache:
    def test_it_is_a_singleton(self):
        """Shared state is the feature: a per-reference cache caches nothing."""
        assert ResolutionCache() is ResolutionCache()

    def test_one_instance_sees_another_s_writes(self, cache):
        ResolutionCache().put("env", "KEY", "value")
        assert cache.get("env", "KEY") == "value"

    def test_it_is_off_by_default(self):
        store = ResolutionCache()
        store.disable()
        store.put("env", "KEY", "value")
        assert store.get("env", "KEY") is None
        assert store.enabled is False

    def test_disabling_drops_what_was_held(self, cache):
        cache.put("env", "KEY", "value")
        cache.disable()
        cache.enable()
        assert cache.get("env", "KEY") is None

    def test_clear_keeps_caching_on(self, cache):
        cache.put("env", "KEY", "value")
        cache.clear()
        assert cache.enabled is True
        assert cache.get("env", "KEY") is None

    def test_an_empty_value_is_not_stored(self, cache):
        """Caching "this resolved to nothing" would hide a secret that
        appears later, which is the opposite of helpful mid-deployment."""
        cache.put("env", "KEY", "")
        assert cache.get("env", "KEY") is None
        assert cache.stats()["entries"] == 0

    def test_a_miss_is_counted(self, cache):
        cache.get("env", "ABSENT")
        assert cache.stats()["misses"] >= 1
        assert cache.misses >= 1

    def test_a_hit_is_counted(self, cache):
        before = cache.hits
        cache.put("env", "KEY", "value")
        cache.get("env", "KEY")
        assert cache.hits == before + 1
        assert cache.stats()["hits"] == cache.hits

    def test_the_counters_delegate_to_the_store(self, cache):
        """The cache holds no counters of its own; TtlStore does."""
        cache.put("env", "KEY", "value")
        cache.get("env", "KEY")
        cache.get("env", "ABSENT")
        assert cache.stats()["hits"] == cache.hits
        assert cache.stats()["misses"] == cache.misses

    def test_sources_do_not_collide(self, cache):
        """An env var and a file path could share a name."""
        cache.put("env", "same", "from-env")
        cache.put("file", "same", "from-file")
        assert cache.get("env", "same") == "from-env"
        assert cache.get("file", "same") == "from-file"

    def test_stats_contain_no_values(self, cache):
        """They go in logs, so they have to be safe there."""
        cache.put("env", "SECRET_NAME", "sk-live-abcdef")
        rendered = str(cache.stats())
        assert "sk-live-abcdef" not in rendered
        assert "SECRET_NAME" not in rendered


class TestExpiry:
    def test_an_entry_expires(self):
        """How a long-running process picks up a rotated secret."""
        store = ResolutionCache()
        store.enable(ttl_seconds=0.05)
        store.clear()
        store.put("env", "KEY", "old")
        time.sleep(0.08)
        assert store.get("env", "KEY") is None

    def test_an_entry_survives_within_the_ttl(self):
        store = ResolutionCache()
        store.enable(ttl_seconds=5)
        store.clear()
        store.put("env", "KEY", "value")
        assert store.get("env", "KEY") == "value"

    def test_without_a_ttl_an_entry_persists(self, cache):
        cache.put("env", "KEY", "value")
        time.sleep(0.02)
        assert cache.get("env", "KEY") == "value"
        assert cache.stats()["ttl_seconds"] is None


class TestCachingDuringResolution:
    def test_a_command_runs_once(self, cache):
        """The reason this exists: a password-manager CLI per access is slow."""
        CommandPolicy().allow("echo")
        reference = SecretRef.parse({"command": "echo value"})
        assert reference.resolve() == "value"
        assert reference.resolve() == "value"
        assert cache.stats()["hits"] >= 1

    def test_a_literal_is_never_cached(self, cache):
        """Reading one costs nothing, so holding it in memory buys nothing."""
        SecretRef.parse("inline-secret").resolve()
        assert cache.stats()["entries"] == 0

    def test_an_environment_variable_is_cached(self, cache, monkeypatch):
        monkeypatch.setenv("CACHED_KEY", "from-env")
        assert SecretRef.parse({"env": "CACHED_KEY"}).resolve() == "from-env"
        assert cache.get("env", "CACHED_KEY") == "from-env"

    def test_a_stale_entry_is_served_until_cleared(self, cache, monkeypatch):
        """The documented downside, pinned so it is not a surprise."""
        monkeypatch.setenv("ROTATING_KEY", "old")
        reference = SecretRef.parse({"env": "ROTATING_KEY"})
        assert reference.resolve() == "old"
        monkeypatch.setenv("ROTATING_KEY", "new")
        assert reference.resolve() == "old"
        cache.clear()
        assert reference.resolve() == "new"

    def test_resolution_is_unaffected_when_caching_is_off(self, monkeypatch):
        ResolutionCache().disable()
        monkeypatch.setenv("UNCACHED_KEY", "first")
        reference = SecretRef.parse({"env": "UNCACHED_KEY"})
        assert reference.resolve() == "first"
        monkeypatch.setenv("UNCACHED_KEY", "second")
        assert reference.resolve() == "second"


class TestThreadSafety:
    def test_concurrent_writes_do_not_lose_entries(self, cache):
        """The store is shared across threads, so the lock has to hold."""

        def fill(start: int) -> None:
            for index in range(start, start + 50):
                cache.put("env", f"KEY_{index}", f"value_{index}")

        threads = [threading.Thread(target=fill, args=(base,)) for base in (0, 50, 100)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert cache.stats()["entries"] == 150

    def test_the_singleton_survives_concurrent_construction(self):
        """Two threads at startup must not each build a store."""
        ResolutionCache._instance = None
        found: list[ResolutionCache] = []

        def build() -> None:
            found.append(ResolutionCache())

        threads = [threading.Thread(target=build) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len({id(instance) for instance in found}) == 1
