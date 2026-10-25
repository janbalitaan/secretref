"""YAML config files, which the README documents and nothing tested.

The whole code path had zero coverage: a documented feature that might never
have worked. These are the tests that would have caught that.
"""

from __future__ import annotations

import builtins
import sys

import pytest

from secretref import ConfigError, ResolutionError, SecretRef, load

pytest.importorskip("yaml", reason="the yaml extra is not installed")

SAMPLE = """\
providers:
  - name: openai
    api_key:
      env: TEST_YAML_KEY
  - name: local
    api_key:
      file: /run/secrets/local
timeout_seconds: 30
languages:
  - en
  - fil
"""


class TestYamlConfigs:
    @pytest.mark.parametrize("suffix", [".yaml", ".yml"])
    def test_both_extensions_load(self, tmp_path, suffix):
        path = tmp_path / f"config{suffix}"
        path.write_text(SAMPLE)
        assert load(path).get("timeout_seconds") == 30

    def test_nested_values_resolve(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(SAMPLE)
        assert load(path).get("providers.0.name") == "openai"

    def test_lists_load(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(SAMPLE)
        assert load(path).get("languages") == ["en", "fil"]

    def test_references_work_the_same(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_YAML_KEY", "sk-from-yaml")
        path = tmp_path / "config.yaml"
        path.write_text(SAMPLE)
        config = load(path)
        assert config.secret("providers.0.api_key").resolve() == "sk-from-yaml"
        assert len(config.secrets()) == 2

    def test_a_config_is_found_by_name(self, tmp_path):
        (tmp_path / "config.yaml").write_text(SAMPLE)
        assert load(root=tmp_path).get("timeout_seconds") == 30

    def test_malformed_yaml_says_so(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("providers:\n  - name: openai\n   bad: indent\n")
        with pytest.raises(Exception) as caught:
            load(path)
        assert caught.type is not AssertionError

    def test_a_top_level_list_is_refused(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("- one\n- two\n")
        with pytest.raises(ConfigError, match="mapping at the top level"):
            load(path)

    def test_safe_load_is_used(self, tmp_path):
        """A config file must not be able to construct arbitrary objects.

        `yaml.load` would run this tag; `yaml.safe_load` refuses it. A config
        file is often less trusted than the code that reads it.
        """
        path = tmp_path / "config.yaml"
        path.write_text("value: !!python/object/apply:os.system ['echo hi']\n")
        with pytest.raises(Exception) as caught:
            load(path)
        assert caught.type is not AssertionError


class TestUnreadableFiles:
    def test_a_directory_is_not_a_config(self, tmp_path):
        directory = tmp_path / "config.json"
        directory.mkdir()
        with pytest.raises(ConfigError, match="cannot read"):
            load(directory)

    def test_an_explicit_literal_mapping_parses(self):
        """The `{"literal": ...}` form, which lets a caller be explicit that
        a value is inline rather than a reference."""
        assert SecretRef.parse({"literal": "inline-value"}).resolve() == "inline-value"

    def test_an_unparseable_command_says_so(self):
        with pytest.raises(ResolutionError, match="not a parseable command"):
            SecretRef.parse({"command": 'op read "unclosed'}).resolve()


class TestYamlWithoutPyyaml:
    """The branch that runs when the optional extra is not installed.

    Reached by hiding the module rather than by uninstalling it, so the test
    works whether or not the extra is present. Without this the error message
    a user without the extra sees would never be exercised.
    """

    @pytest.fixture
    def without_yaml(self, monkeypatch):
        """Make `import yaml` fail, as it would in a default install."""
        real_import = builtins.__import__

        def refuse(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", refuse)
        monkeypatch.delitem(sys.modules, "yaml", raising=False)

    def test_it_names_the_extra_to_install(self, tmp_path, without_yaml):
        path = tmp_path / "config.yaml"
        path.write_text("a: 1\n")
        with pytest.raises(ConfigError, match=r"secretref\[yaml\]"):
            load(path)

    def test_the_message_names_the_file(self, tmp_path, without_yaml):
        path = tmp_path / "config.yml"
        path.write_text("a: 1\n")
        with pytest.raises(ConfigError, match=r"config\.yml"):
            load(path)

    def test_json_still_works_without_the_extra(self, tmp_path, without_yaml):
        """The extra is optional, so its absence must not affect JSON."""
        path = tmp_path / "config.json"
        path.write_text('{"a": 1}')
        assert load(path).get("a") == 1
