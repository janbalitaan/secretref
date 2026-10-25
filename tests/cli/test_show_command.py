"""Listing what a config references, which reads nothing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secretref.cli import ExitCode, main

SAMPLE = {
    "database": {"password": {"env": "DATABASE_PASSWORD"}},
    "cache": {"password": {"file": "/run/secrets/redis"}},
    "region": {"env": "AWS_REGION", "default": "us-east-1"},
    "smtp": {"env": "SMTP_PASSWORD", "required": False},
    "host": "db.internal",
}


@pytest.fixture
def config(tmp_path) -> Path:
    (tmp_path / "config.json").write_text(json.dumps(SAMPLE))
    return tmp_path


class TestShowCommand:
    def test_it_exits_zero(self, config):
        assert main(["show", "--root", str(config)]) == ExitCode.OK

    def test_it_lists_every_reference(self, config, capsys):
        printed = capsys.readouterr
        main(["show", "--root", str(config)])
        out = printed().out
        for path in ("database.password", "cache.password", "region", "smtp"):
            assert path in out

    def test_it_does_not_list_a_plain_value(self, config, capsys):
        """`host` is configuration, not a reference."""
        main(["show", "--root", str(config)])
        assert "db.internal" not in capsys.readouterr().out

    def test_it_names_the_source(self, config, capsys):
        main(["show", "--root", str(config)])
        out = capsys.readouterr().out
        assert "env 'DATABASE_PASSWORD'" in out
        assert "/run/secrets/redis" in out

    def test_it_marks_an_optional_reference(self, config, capsys):
        main(["show", "--root", str(config)])
        assert "optional" in capsys.readouterr().out

    def test_it_marks_a_default(self, config, capsys):
        main(["show", "--root", str(config)])
        assert "has a default" in capsys.readouterr().out

    def test_it_counts_them(self, config, capsys):
        main(["show", "--root", str(config)])
        assert "4 references" in capsys.readouterr().out

    def test_a_config_with_none_says_so(self, tmp_path, capsys):
        (tmp_path / "config.json").write_text(json.dumps({"host": "x"}))
        main(["show", "--root", str(tmp_path)])
        assert "no references" in capsys.readouterr().out

    def test_a_missing_config_exits_two(self, tmp_path, capsys):
        assert main(["show", "--root", str(tmp_path)]) == ExitCode.USAGE
        assert "error:" in capsys.readouterr().err

    def test_a_named_path_is_used(self, tmp_path):
        path = tmp_path / "elsewhere.json"
        path.write_text(json.dumps(SAMPLE))
        assert main(["show", str(path)]) == ExitCode.OK


class TestShowJson:
    def test_it_is_valid_json(self, config, capsys):
        main(["show", "--root", str(config), "--json"])
        json.loads(capsys.readouterr().out)

    def test_it_carries_each_reference(self, config, capsys):
        main(["show", "--root", str(config), "--json"])
        references = json.loads(capsys.readouterr().out)["references"]
        assert len(references) == 4
        assert {item["path"] for item in references} >= {"database.password", "smtp"}

    def test_it_declares_side_effects(self, config, capsys):
        """So a tool can tell which references it must not resolve."""
        main(["show", "--root", str(config), "--json"])
        references = json.loads(capsys.readouterr().out)["references"]
        assert all(item["side_effects"] is False for item in references)

    def test_it_declares_optionality_and_defaults(self, config, capsys):
        main(["show", "--root", str(config), "--json"])
        by_path = {
            item["path"]: item for item in json.loads(capsys.readouterr().out)["references"]
        }
        assert by_path["smtp"]["required"] is False
        assert by_path["region"]["has_default"] is True

    def test_it_never_carries_a_value(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("DATABASE_PASSWORD", "sk-live-abcdef")
        (tmp_path / "config.json").write_text(json.dumps(SAMPLE))
        main(["show", "--root", str(tmp_path), "--json"])
        assert "sk-live-abcdef" not in capsys.readouterr().out
