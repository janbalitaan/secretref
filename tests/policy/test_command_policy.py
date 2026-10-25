"""The policy is what stands between a writable config and code execution.

A command reference is the only reference form that starts a process, so a
config file someone can edit is a config file that can run something. Each
test here corresponds to an exposure that was measured on the real
implementation before the policy existed.
"""

from __future__ import annotations

import pytest

from secretref import CommandNotAllowedError, CommandPolicy, ResolutionError, SecretRef


class TestCommandPolicy:
    def test_commands_are_refused_by_default(self):
        """The one fix that removes the capability rather than narrowing it."""
        with pytest.raises(CommandNotAllowedError, match="off by default"):
            SecretRef.parse({"command": "echo hello"}).resolve()

    def test_the_refusal_says_how_to_enable_it(self):
        """A security default that does not explain itself gets worked around."""
        with pytest.raises(CommandNotAllowedError, match="CommandPolicy"):
            SecretRef.parse({"command": "echo hello"}).resolve()

    def test_an_allowed_executable_runs(self):
        CommandPolicy().allow("echo")
        assert SecretRef.parse({"command": "echo hello"}).resolve() == "hello"

    def test_an_executable_not_on_the_list_is_refused(self):
        CommandPolicy().allow("op", "vault")
        with pytest.raises(CommandNotAllowedError, match="allows: op, vault"):
            SecretRef.parse({"command": "echo hello"}).resolve()

    def test_an_empty_allowlist_permits_anything(self):
        """Has to be asked for explicitly, which is the point."""
        CommandPolicy().allow()
        assert SecretRef.parse({"command": "echo hello"}).resolve() == "hello"

    def test_a_path_is_matched_on_its_basename(self):
        """So allowing "op" permits /usr/local/bin/op."""
        CommandPolicy().allow("echo")
        found = SecretRef.parse({"command": "/bin/echo hello"})
        assert found.resolve() == "hello"

    def test_absolute_paths_can_be_required(self):
        """A bare name resolves through PATH, which a caller may control."""
        CommandPolicy().allow("echo", require_absolute=True)
        with pytest.raises(CommandNotAllowedError, match="absolute path"):
            SecretRef.parse({"command": "echo hello"}).resolve()

    def test_an_absolute_path_satisfies_that(self):
        CommandPolicy().allow("echo", require_absolute=True)
        assert SecretRef.parse({"command": "/bin/echo hello"}).resolve() == "hello"

    def test_an_empty_command_is_refused(self):
        CommandPolicy().allow()
        with pytest.raises(CommandNotAllowedError, match="empty command"):
            SecretRef.parse({"command": "   "}).resolve()


class TestEnvironmentIsolation:
    def test_a_command_cannot_read_other_secrets(self, monkeypatch):
        """Measured before the fix: the subprocess inherited everything, so a
        command reference could print a secret it was never given.

        `printenv` exits non-zero for a variable it cannot see, so the proof
        that isolation works is that the command fails — and that the secret
        appears nowhere in the error.
        """
        monkeypatch.setenv("OTHER_TENANT_SECRET", "sk-live-not-yours")
        CommandPolicy().allow("printenv")
        reference = SecretRef.parse({"command": "printenv OTHER_TENANT_SECRET"})
        with pytest.raises(ResolutionError) as caught:
            reference.resolve()
        assert "sk-live-not-yours" not in str(caught.value)

    def test_the_minimal_environment_is_enough_to_start_a_cli(self):
        """A tool that cannot see PATH cannot run at all."""
        CommandPolicy().allow("printenv")
        assert SecretRef.parse({"command": "printenv PATH"}).resolve()

    def test_a_caller_can_pass_a_named_variable(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.internal")
        CommandPolicy().allow("printenv", pass_environment=["VAULT_ADDR"])
        assert (
            SecretRef.parse({"command": "printenv VAULT_ADDR"}).resolve()
            == "https://vault.internal"
        )

    def test_naming_one_does_not_drop_the_minimal_set(self):
        CommandPolicy().allow("printenv", pass_environment=["VAULT_ADDR"])
        assert SecretRef.parse({"command": "printenv PATH"}).resolve()

    def test_the_environment_contains_only_what_is_named(self, monkeypatch):
        monkeypatch.setenv("UNRELATED", "value")
        CommandPolicy().allow()
        assert "UNRELATED" not in CommandPolicy().environment()


class TestResourceLimits:
    def test_output_is_capped(self):
        """A secret is short. More than the cap is the wrong command or an
        attempt to exhaust memory."""
        CommandPolicy().allow("head", max_output_bytes=1024)
        with pytest.raises(ResolutionError, match="more than 1024 bytes"):
            SecretRef.parse({"command": "head -c 50000 /dev/zero"}).resolve()

    def test_output_under_the_cap_is_returned(self):
        CommandPolicy().allow("echo", max_output_bytes=1024)
        assert SecretRef.parse({"command": "echo short"}).resolve() == "short"

    def test_a_slow_command_times_out(self):
        CommandPolicy().allow("sleep", timeout_seconds=0.1)
        with pytest.raises(ResolutionError, match="did not finish"):
            SecretRef.parse({"command": "sleep 5"}).resolve()

    def test_the_timeout_message_names_the_limit(self):
        CommandPolicy().allow("sleep", timeout_seconds=0.1)
        with pytest.raises(ResolutionError, match=r"0\.1s"):
            SecretRef.parse({"command": "sleep 5"}).resolve()


class TestShellIsNotUsed:
    def test_a_semicolon_is_an_argument(self):
        """Split with shlex and run without a shell, so this is one echo."""
        CommandPolicy().allow("echo")
        assert SecretRef.parse({"command": "echo a; echo b"}).resolve() == "a; echo b"

    def test_a_pipe_is_an_argument(self):
        CommandPolicy().allow("echo")
        assert "|" in SecretRef.parse({"command": "echo a | tee /tmp/x"}).resolve()

    def test_backticks_are_arguments(self):
        CommandPolicy().allow("echo")
        assert "`" in SecretRef.parse({"command": "echo `id`"}).resolve()


class TestPolicyItself:
    def test_it_is_a_singleton(self):
        """One decision made at startup that every resolution has to see."""
        assert CommandPolicy() is CommandPolicy()

    def test_forbid_returns_to_the_safe_position(self):
        CommandPolicy().allow("echo")
        assert CommandPolicy().enabled is True
        CommandPolicy().forbid()
        assert CommandPolicy().enabled is False

    def test_describe_is_safe_to_log(self):
        CommandPolicy().allow("op", pass_environment=["VAULT_TOKEN"])
        described = CommandPolicy().describe()
        assert "op" in described
        assert "VAULT_TOKEN" not in described

    def test_describe_says_when_it_is_off(self):
        assert CommandPolicy().describe() == "command references: off"

    def test_a_working_directory_can_be_pinned(self, tmp_path):
        CommandPolicy().allow("pwd", working_directory=tmp_path)
        assert SecretRef.parse({"command": "pwd"}).resolve() == str(tmp_path)

    def test_the_default_inherits_the_working_directory(self):
        assert CommandPolicy().working_directory is None


class TestExecutablePinning:
    """`allow("op")` resolves the executable when the policy is configured.

    Permitting a bare name and resolving it at use time meant an attacker who
    could prepend a directory to PATH substituted their own script. Resolving
    at configuration time pins the file while PATH is still the one the
    operator started with.
    """

    def test_an_absolute_name_is_pinned_directly(self):
        """No PATH lookup needed, so it is pinned as given."""
        CommandPolicy().allow("/bin/echo")
        assert SecretRef.parse({"command": "/bin/echo hello"}).resolve() == "hello"

    def test_an_absolute_name_is_normalized(self, tmp_path):
        """A path with .. in it pins the file it actually refers to."""
        CommandPolicy().allow("/bin/../bin/echo")
        assert SecretRef.parse({"command": "/bin/echo hello"}).resolve() == "hello"

    def test_a_name_found_on_path_is_pinned(self):
        CommandPolicy().allow("echo")
        assert SecretRef.parse({"command": "echo hello"}).resolve() == "hello"

    def test_a_name_not_found_falls_back_to_the_name(self):
        """A policy is often configured before the tool is installed, so an
        unfound name is checked by name rather than failing outright."""
        CommandPolicy().allow("definitely-not-a-real-tool-anywhere")
        with pytest.raises(CommandNotAllowedError, match="not permitted"):
            SecretRef.parse({"command": "echo hello"}).resolve()
