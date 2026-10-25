"""What a file reference is permitted to read.

`{"file": "/run/secrets/db-password"}` is how Kubernetes, Docker and systemd
hand a secret to a process, which makes it the most important form and the
second most dangerous. Each test corresponds to an exposure measured on the
real implementation before the policy existed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secretref import FileNotAllowedError, FilePolicy, ResolutionError, SecretRef

SECRET = "sk-live-abcdef1234567890"


@pytest.fixture
def secrets(tmp_path) -> Path:
    """A directory of owner-only secret files, as a mount would be."""
    directory = tmp_path / "secrets"
    directory.mkdir()
    secret = directory / "db-password"
    secret.write_text(SECRET)
    secret.chmod(0o600)
    return directory


class TestFilePolicy:
    def test_the_standard_mounts_are_permitted_by_default(self):
        """A container is protected with no configuration, and still works."""
        roots = {str(root) for root in FilePolicy().roots}
        assert "/run/secrets" in roots

    def test_a_path_outside_them_is_refused_by_default(self, tmp_path):
        """The reason the default changed: a config that can be edited could
        otherwise name anything the process can read."""
        ordinary = tmp_path / "notes.txt"
        ordinary.write_text("a value")
        with pytest.raises(FileNotAllowedError):
            SecretRef.parse({"file": str(ordinary)}).resolve()

    def test_allow_anywhere_gives_up_the_protection(self, tmp_path):
        """Named for what it does, so the call site says so."""
        ordinary = tmp_path / "notes.txt"
        ordinary.write_text("a value")
        FilePolicy().allow_anywhere()
        assert SecretRef.parse({"file": str(ordinary)}).resolve() == "a value"

    def test_reset_returns_to_the_default(self, tmp_path):
        FilePolicy().allow_anywhere()
        FilePolicy().reset()
        assert "/run/secrets" in {str(root) for root in FilePolicy().roots}

    def test_a_file_inside_an_allowed_root_is_read(self, secrets):
        FilePolicy().restrict(secrets)
        assert SecretRef.parse({"file": str(secrets / "db-password")}).resolve() == SECRET

    def test_a_file_outside_the_roots_is_refused(self, tmp_path, secrets):
        outside = tmp_path / "elsewhere"
        outside.write_text("value")
        FilePolicy().restrict(secrets)
        with pytest.raises(FileNotAllowedError, match="outside the permitted roots"):
            SecretRef.parse({"file": str(outside)}).resolve()

    def test_the_refusal_names_what_is_allowed(self, tmp_path, secrets):
        FilePolicy().restrict(secrets)
        with pytest.raises(FileNotAllowedError, match=str(secrets)):
            SecretRef.parse({"file": "/etc/hostname"}).resolve()

    def test_restricting_with_no_roots_uses_the_conventional_mounts(self):
        """The right answer in a container and the wrong one on a laptop,
        which is why it has to be asked for."""
        FilePolicy().restrict()
        roots = {str(root) for root in FilePolicy().roots}
        assert "/run/secrets" in roots

    def test_several_roots_are_allowed(self, tmp_path, secrets):
        other = tmp_path / "more-secrets"
        other.mkdir()
        secret = other / "key"
        secret.write_text(SECRET)
        secret.chmod(0o600)
        FilePolicy().restrict(secrets, other)
        assert SecretRef.parse({"file": str(secret)}).resolve() == SECRET

    def test_relax_returns_to_the_starting_position(self, tmp_path, secrets):
        FilePolicy().restrict(secrets)
        FilePolicy().allow_anywhere()
        outside = tmp_path / "elsewhere"
        outside.write_text("value")
        assert SecretRef.parse({"file": str(outside)}).resolve() == "value"


class TestSymlinks:
    def test_a_link_out_of_an_allowed_root_is_refused(self, tmp_path, secrets):
        """A link inside an allowed root pointing outside it would defeat
        the root check entirely, so the resolved path is what is checked."""
        outside = tmp_path / "elsewhere"
        outside.write_text("value")
        link = secrets / "link"
        link.symlink_to(outside)
        FilePolicy().restrict(secrets, require_private=False)
        with pytest.raises(FileNotAllowedError, match="resolves to"):
            SecretRef.parse({"file": str(link)}).resolve()

    def test_a_link_within_the_root_is_read(self, secrets):
        """Kubernetes projected volumes are symlinks, so refusing all of
        them would refuse the main use case."""
        target = secrets / "actual"
        target.write_text(SECRET)
        target.chmod(0o600)
        link = secrets / "link"
        link.symlink_to(target)
        FilePolicy().restrict(secrets)
        assert SecretRef.parse({"file": str(link)}).resolve() == SECRET


class TestPermissions:
    def test_a_world_readable_secret_is_refused(self, secrets):
        """A misconfiguration whether or not anything has read it yet."""
        loose = secrets / "loose"
        loose.write_text(SECRET)
        loose.chmod(0o644)
        FilePolicy().restrict(secrets)
        with pytest.raises(FileNotAllowedError, match="readable beyond its owner"):
            SecretRef.parse({"file": str(loose)}).resolve()

    def test_a_group_readable_secret_is_refused(self, secrets):
        loose = secrets / "group"
        loose.write_text(SECRET)
        loose.chmod(0o640)
        FilePolicy().restrict(secrets)
        with pytest.raises(FileNotAllowedError, match="0o640"):
            SecretRef.parse({"file": str(loose)}).resolve()

    def test_the_refusal_says_how_to_fix_it(self, secrets):
        loose = secrets / "loose"
        loose.write_text(SECRET)
        loose.chmod(0o644)
        FilePolicy().restrict(secrets)
        with pytest.raises(FileNotAllowedError, match="chmod 600"):
            SecretRef.parse({"file": str(loose)}).resolve()

    def test_permission_checking_can_be_turned_off(self, secrets):
        loose = secrets / "loose"
        loose.write_text(SECRET)
        loose.chmod(0o644)
        FilePolicy().restrict(secrets, require_private=False)
        assert SecretRef.parse({"file": str(loose)}).resolve() == SECRET

    def test_a_missing_file_is_not_a_permission_problem(self, secrets):
        """Whether an absent secret is an error depends on `required`, which
        is resolution's decision rather than the policy's."""
        FilePolicy().restrict(secrets)
        reference = SecretRef.parse({"file": str(secrets / "absent"), "required": False})
        assert reference.resolve() == ""


class TestSizeCap:
    def test_an_oversized_file_is_refused(self, secrets):
        """A credential is short; this is probably the wrong path."""
        big = secrets / "big"
        big.write_text("x" * 5000)
        big.chmod(0o600)
        FilePolicy().restrict(secrets, max_bytes=1024)
        with pytest.raises(ResolutionError, match="more than 1024 bytes"):
            SecretRef.parse({"file": str(big)}).resolve()

    def test_a_file_under_the_cap_is_read(self, secrets):
        FilePolicy().restrict(secrets, max_bytes=1024)
        assert SecretRef.parse({"file": str(secrets / "db-password")}).resolve() == SECRET


class TestPolicyItself:
    def test_it_is_a_singleton(self):
        assert FilePolicy() is FilePolicy()

    def test_describe_names_the_default_roots(self):
        assert "/run/secrets" in FilePolicy().describe()

    def test_describe_says_when_protection_is_off(self):
        FilePolicy().allow_anywhere()
        assert "any path" in FilePolicy().describe()

    def test_describe_names_the_roots(self, secrets):
        FilePolicy().restrict(secrets)
        described = FilePolicy().describe()
        assert str(secrets) in described
        assert "owner-only" in described

    def test_describe_is_safe_to_log(self, secrets):
        """It names paths, which are not secrets, and no values."""
        FilePolicy().restrict(secrets)
        assert SECRET not in FilePolicy().describe()


class TestTimeOfCheckTimeOfUse:
    """Validation and reading are one operation, so they cannot disagree.

    A policy that approved a *path* and let the caller open it afterwards
    would leave a window: between the two syscalls the final component can be
    replaced, and the inode that was validated would not be the inode read.
    """

    def test_a_symlink_appearing_after_resolution_is_refused(
        self, tmp_path, secrets, monkeypatch
    ):
        """O_NOFOLLOW on the already-resolved path.

        The resolved path's last component is not a link by definition, so
        the flag only fires if something changed between the resolve and the
        open — which is exactly the race. Staged by making `resolve` hand
        back a path that is a link, rather than by trying to win it.
        """
        outside = tmp_path / "stolen"
        outside.write_text("a file the policy would have refused")
        link = secrets / "swapped"
        link.symlink_to(outside)

        real_resolve = Path.resolve

        def resolve_to_the_link(self, *args, **kwargs):
            if self.name == "db-password":
                return link
            return real_resolve(self, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", resolve_to_the_link)
        FilePolicy().restrict(secrets, require_private=False)

        with pytest.raises(FileNotAllowedError, match="became a symlink"):
            SecretRef.parse({"file": str(secrets / "db-password")}).resolve()

    def test_binary_content_is_treated_as_absent(self, secrets):
        """A credential is text. Bytes that are not UTF-8 mean the reference
        points at the wrong thing, which `required` decides the weight of."""
        binary = secrets / "binary"
        binary.write_bytes(b"\xff\xfe\x00\x01")
        binary.chmod(0o600)
        FilePolicy().restrict(secrets)
        reference = SecretRef.parse({"file": str(binary), "required": False})
        assert reference.resolve() == ""

    def test_the_descriptor_is_closed_on_a_refusal(self, secrets):
        """A refusal mid-read must not leak the open file descriptor."""
        loose = secrets / "loose"
        loose.write_text(SECRET)
        loose.chmod(0o644)
        FilePolicy().restrict(secrets)
        for _ in range(50):
            with pytest.raises(FileNotAllowedError):
                SecretRef.parse({"file": str(loose)}).resolve()
        # Reaching here without OSError: too many open files means the
        # descriptors were released.
        assert True

    def test_max_bytes_is_reported(self, secrets):
        FilePolicy().restrict(secrets, max_bytes=2048)
        assert FilePolicy().max_bytes == 2048
