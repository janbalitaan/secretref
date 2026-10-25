"""Loading a file and reaching into it by dotted path."""

from __future__ import annotations

import json

import pytest

from secretref import load, loads
from secretref.exceptions import ConfigError

SAMPLE = {
    "providers": [
        {"name": "openai", "api_key": {"env": "TEST_KEY"}},
        {"name": "local", "api_key": {"file": "/run/secrets/local"}},
    ],
    "timeout_seconds": 30,
    "languages": ["en", "fil"],
    "nested": {"deep": {"value": True}},
}


class TestReadingAConfig:
    def test_a_plain_value(self):
        assert loads(json.dumps(SAMPLE)).get("timeout_seconds") == 30

    def test_a_list_value(self):
        assert loads(json.dumps(SAMPLE)).get("languages") == ["en", "fil"]

    def test_a_nested_value(self):
        assert loads(json.dumps(SAMPLE)).get("nested.deep.value") is True

    def test_a_list_index(self):
        """A list of providers is the shape this problem actually takes."""
        assert loads(json.dumps(SAMPLE)).get("providers.0.name") == "openai"

    def test_an_absent_path_returns_the_default(self):
        assert loads(json.dumps(SAMPLE)).get("nope.at.all", "fallback") == "fallback"

    def test_require_raises_on_an_absent_path(self):
        with pytest.raises(ConfigError, match="has no"):
            loads(json.dumps(SAMPLE)).require("nope")

    def test_an_out_of_range_index_is_absent_not_an_error(self):
        assert loads(json.dumps(SAMPLE)).get("providers.9.name") is None

    def test_a_secret_comes_back_as_a_reference(self, monkeypatch):
        """Returning the reference keeps resolving a separate, visible step."""
        monkeypatch.setenv("TEST_KEY", "sk-resolved")
        reference = loads(json.dumps(SAMPLE)).secret("providers.0.api_key")
        assert reference.described() == "env 'TEST_KEY'"
        assert reference.resolve() == "sk-resolved"

    def test_every_reference_can_be_listed(self):
        """For a startup check that reports all the missing secrets at once."""
        found = loads(json.dumps(SAMPLE)).secrets()
        assert set(found) == {"providers.0.api_key", "providers.1.api_key"}

    def test_the_raw_data_holds_mappings_not_values(self):
        """So nothing reads a secret by accident, including a print of it."""
        data = loads(json.dumps(SAMPLE)).data
        assert data["providers"][0]["api_key"] == {"env": "TEST_KEY"}

    def test_loading_from_a_file(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(SAMPLE))
        assert load(path).get("timeout_seconds") == 30

    def test_the_path_is_recorded(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("{}")
        assert load(path).path == path

    def test_a_config_found_by_name(self, tmp_path):
        (tmp_path / "config.json").write_text(json.dumps(SAMPLE))
        assert load(root=tmp_path).get("timeout_seconds") == 30

    def test_no_config_raises_with_what_it_looked_for(self, tmp_path):
        with pytest.raises(ConfigError, match=r"config\.json"):
            load(root=tmp_path)

    def test_invalid_json_says_so(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("{not json")
        with pytest.raises(ConfigError, match="not valid JSON"):
            load(path)

    def test_a_top_level_list_is_refused(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("[1, 2]")
        with pytest.raises(ConfigError, match="object at the top level"):
            load(path)

    def test_a_malformed_secret_mapping_names_the_path(self):
        config = loads(json.dumps({"api_key": {"envv": "TYPO"}}))
        with pytest.raises(ConfigError, match="api_key"):
            config.secret("api_key")
