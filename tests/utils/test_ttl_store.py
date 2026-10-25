"""A key-value store that forgets, with no knowledge of secrets.

Separated from `ResolutionCache` because the mechanics are reusable and the
domain rules are not. These tests cover the mechanics; the cache's own tests
cover what is specific to resolving a reference.
"""

from __future__ import annotations

import threading
import time

from secretref.utils import TtlStore


class TestTtlStore:
    def test_a_value_comes_back(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("key", "value")
        assert store.get("key") == "value"

    def test_an_absent_key_is_none(self):
        assert TtlStore().get("nothing") is None

    def test_a_hit_is_counted(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("key", "value")
        store.get("key")
        assert store.hits == 1
        assert store.misses == 0

    def test_a_miss_is_counted(self):
        store: TtlStore[str, str] = TtlStore()
        store.get("absent")
        assert store.misses == 1
        assert store.hits == 0

    def test_clear_drops_everything(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("key", "value")
        store.clear()
        assert store.get("key") is None
        assert len(store) == 0

    def test_a_tuple_key_works(self):
        """What ResolutionCache uses, so an env var and a file path that
        share a name do not collide."""
        store: TtlStore[tuple[str, str], str] = TtlStore()
        store.put(("env", "same"), "from-env")
        store.put(("file", "same"), "from-file")
        assert store.get(("env", "same")) == "from-env"
        assert store.get(("file", "same")) == "from-file"

    def test_counters_contain_no_keys_or_values(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("SECRET_NAME", "sk-live-abcdef")
        rendered = str(store.counters())
        assert "SECRET_NAME" not in rendered
        assert "sk-live-abcdef" not in rendered

    def test_length_reports_what_is_held(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("a", "1")
        store.put("b", "2")
        assert len(store) == 2


class TestExpiry:
    def test_an_entry_expires(self):
        store: TtlStore[str, str] = TtlStore(ttl_seconds=0.05)
        store.put("key", "value")
        time.sleep(0.08)
        assert store.get("key") is None

    def test_an_expired_entry_is_dropped_on_the_way_out(self):
        """No sweep and no background thread: for a handful of entries,
        dropping on read is enough."""
        store: TtlStore[str, str] = TtlStore(ttl_seconds=0.05)
        store.put("key", "value")
        time.sleep(0.08)
        store.get("key")
        assert len(store) == 0

    def test_an_entry_survives_within_the_ttl(self):
        store: TtlStore[str, str] = TtlStore(ttl_seconds=5)
        store.put("key", "value")
        assert store.get("key") == "value"

    def test_without_a_ttl_an_entry_persists(self):
        store: TtlStore[str, str] = TtlStore()
        store.put("key", "value")
        time.sleep(0.02)
        assert store.get("key") == "value"
        assert store.ttl is None

    def test_the_ttl_can_be_changed_afterwards(self):
        """Existing entries are judged by the new lifetime, which is what
        lets a cache be tightened without being cleared."""
        store: TtlStore[str, str] = TtlStore()
        store.put("key", "value")
        store.ttl = 0.0
        time.sleep(0.01)
        assert store.get("key") is None


class TestThreadSafety:
    def test_concurrent_writes_do_not_lose_entries(self):
        store: TtlStore[str, str] = TtlStore()

        def fill(start: int) -> None:
            for index in range(start, start + 50):
                store.put(f"key_{index}", f"value_{index}")

        threads = [threading.Thread(target=fill, args=(base,)) for base in (0, 50, 100)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(store) == 150

    def test_it_is_not_a_singleton(self):
        """Whether a store is shared is the caller's decision, and
        ResolutionCache is the one that makes it."""
        assert TtlStore() is not TtlStore()
