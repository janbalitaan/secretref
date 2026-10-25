"""Printing a Config must not print what it holds.

The contents may include a literal secret — that is what `audit()` reports —
so a repr that dumped them would be the mistake this library prevents.
"""

from __future__ import annotations

import json

from secretref import load, loads


class TestConfigPrinting:
    def test_a_config_from_a_string_says_so(self):
        assert repr(loads('{"a": 1}')) == "Config(path='<string>', keys=1)"

    def test_a_config_from_a_file_names_it(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"a": 1, "b": 2}))
        rendered = repr(load(path))
        assert "config.json" in rendered
        assert "keys=2" in rendered

    def test_the_contents_are_not_printed(self):
        secret = "sk-live-abcdef1234567890"
        assert secret not in repr(loads(json.dumps({"api_key": secret})))
