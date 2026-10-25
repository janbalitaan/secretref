"""Which environment variables a config may reference.

The obvious objection is that the process already holds every variable, so
reading one through a reference grants nothing new. True, and beside the
point: the threat is redirecting an existing data flow to carry something out
of the environment. A field the application displays, repointed from
SUPPORT_EMAIL to AWS_SECRET_ACCESS_KEY, leaks a key without the attacker
touching the environment at all.
"""

from __future__ import annotations

import pytest

from secretref import EnvironmentPolicy, SecretRef, VariableNotAllowedError


@pytest.fixture(autouse=True)
def variables(monkeypatch):
    """One variable a config should reach, and one it should not."""
    monkeypatch.setenv("MYAPP_DB_PASSWORD", "legitimate")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")


class TestEnvironmentPolicy:
    def test_any_variable_is_readable_by_default(self):
        """Restricting by default would reject every config written before
        the policy existed, for a threat that needs a writable config."""
        assert SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_an_exact_name_is_permitted(self):
        EnvironmentPolicy().restrict("MYAPP_DB_PASSWORD")
        assert SecretRef.parse({"env": "MYAPP_DB_PASSWORD"}).resolve() == "legitimate"

    def test_a_name_not_listed_is_refused(self):
        EnvironmentPolicy().restrict("MYAPP_DB_PASSWORD")
        with pytest.raises(VariableNotAllowedError):
            SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_the_refusal_says_what_is_permitted(self):
        EnvironmentPolicy().restrict("MYAPP_DB_PASSWORD")
        with pytest.raises(VariableNotAllowedError, match="MYAPP_DB_PASSWORD"):
            SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_a_prefix_permits_a_namespace(self):
        EnvironmentPolicy().restrict(prefixes=["MYAPP_"])
        assert SecretRef.parse({"env": "MYAPP_DB_PASSWORD"}).resolve() == "legitimate"
        with pytest.raises(VariableNotAllowedError):
            SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_a_pattern_permits_a_convention(self):
        EnvironmentPolicy().restrict(patterns=[r"^MYAPP_"])
        assert SecretRef.parse({"env": "MYAPP_DB_PASSWORD"}).resolve() == "legitimate"
        with pytest.raises(VariableNotAllowedError):
            SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_the_mechanisms_combine(self):
        EnvironmentPolicy().restrict("EXACT_ONE", prefixes=["MYAPP_"])
        assert EnvironmentPolicy().permits("EXACT_ONE")
        assert EnvironmentPolicy().permits("MYAPP_ANYTHING")
        assert not EnvironmentPolicy().permits("OTHER")

    def test_restricting_with_nothing_switches_references_off(self):
        """ "Restricted to nothing" and "not restricted" are different
        states, and the first is a useful off switch."""
        EnvironmentPolicy().restrict()
        assert EnvironmentPolicy().restricted is True
        with pytest.raises(VariableNotAllowedError):
            SecretRef.parse({"env": "MYAPP_DB_PASSWORD"}).resolve()

    def test_relax_returns_to_the_starting_position(self):
        EnvironmentPolicy().restrict()
        EnvironmentPolicy().relax()
        assert EnvironmentPolicy().restricted is False
        assert SecretRef.parse({"env": "MYAPP_DB_PASSWORD"}).resolve() == "legitimate"

    def test_the_threat_this_closes(self):
        """A field the application displays, repointed at a secret."""
        displayed = SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"})
        EnvironmentPolicy().restrict(prefixes=["MYAPP_", "SUPPORT_"])
        with pytest.raises(VariableNotAllowedError):
            displayed.resolve()


class TestReporting:
    def test_visible_lists_names_without_values(self):
        """For a startup check: knowing what a config may reach beats
        discovering it from a refusal."""
        EnvironmentPolicy().restrict(prefixes=["MYAPP_"])
        visible = EnvironmentPolicy().visible()
        assert "MYAPP_DB_PASSWORD" in visible
        assert "AWS_SECRET_ACCESS_KEY" not in visible
        assert "legitimate" not in str(visible)

    def test_visible_covers_everything_when_unrestricted(self):
        assert "AWS_SECRET_ACCESS_KEY" in EnvironmentPolicy().visible()

    def test_describe_says_when_it_is_open(self):
        assert EnvironmentPolicy().describe() == "environment references: any variable"

    def test_describe_names_each_mechanism(self):
        EnvironmentPolicy().restrict("ONE", prefixes=["TWO_"], patterns=[r"THREE$"])
        described = EnvironmentPolicy().describe()
        assert "ONE" in described
        assert "TWO_" in described
        assert "THREE$" in described

    def test_describe_says_when_nothing_is_permitted(self):
        EnvironmentPolicy().restrict()
        assert "nothing" in EnvironmentPolicy().describe()

    def test_describe_is_safe_to_log(self):
        """It names variables, which are not secrets, and no values."""
        EnvironmentPolicy().restrict("MYAPP_DB_PASSWORD")
        assert "legitimate" not in EnvironmentPolicy().describe()

    def test_it_is_a_singleton(self):
        assert EnvironmentPolicy() is EnvironmentPolicy()
