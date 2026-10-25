"""Running the checks over one config file."""

from __future__ import annotations

from secretref.auditors.known_format import KnownFormat
from secretref.auditors.placeholder import Placeholder
from secretref.auditors.secret_key import SecretKey
from secretref.models.config import Config
from secretref.models.finding import Finding, Severity
from secretref.models.source import Source
from secretref.utils.repository import Repository
from secretref.utils.tree import Tree


class Auditor:
    """Carries the config and the repository verdict through the checks.

    A class because every check needs both, and threading them through
    arguments made the functions longer than the checks they performed.
    """

    def __init__(self, config: Config, *, resolve: bool = False) -> None:
        """Audit a config, optionally checking that its secrets resolve.

        `resolve` is off by default, and that default is a security
        boundary rather than a performance one. Resolving a command
        reference *runs* it, so an audit that resolved would execute
        whatever the config asked for — and auditing a config you did not
        write is the main use for this. A CI check on a pull request would
        have been remote code execution.

        Turn it on for your own config at startup, where knowing a secret
        is actually reachable is worth more than the caution.
        """
        self._config = config
        self._resolve = resolve
        self._repository = Repository.root(config.path) if config.path else None

    def run(self) -> list[Finding]:
        """Run every check and order the results by severity."""
        findings = [*self._reference_findings(), *self._literal_findings()]
        order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}
        findings.sort(key=lambda finding: (order[finding.severity], finding.path))
        return findings

    def _may_check(self, reference) -> bool:
        """Whether this reference can be verified without doing anything.

        A reference with side effects is only resolved when the caller has
        said the config is theirs.
        """
        return self._resolve or not reference.has_side_effects()

    # -- checks -----------------------------------------------------------

    def _reference_findings(self) -> list[Finding]:
        """Problems with values that are already references."""
        findings = []
        for path, reference in self._config.secrets().items():
            if reference.source is Source.LITERAL:
                findings.append(self._literal_finding(path, reference.locator))
            elif broken := reference.malformed():
                # Checked first: a reference that cannot be parsed will not
                # work whatever the policy says, and naming the syntax error
                # is more useful than reporting it as unverified.
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        path=path,
                        message=f"{reference.described()} is {broken}",
                        remedy="fix the reference in the config",
                    )
                )
            elif refused := reference.refusal():
                # A policy refusal is a config error, not a deployment one:
                # the config asks for something it is not permitted to do,
                # and no amount of setting variables will change that. An
                # error whatever the repository, because the application
                # will not start.
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        path=path,
                        message=f"refused by policy — {refused.rstrip('.')}",
                        remedy="widen the policy, or point the reference somewhere it permits",
                    )
                )
            elif not self._may_check(reference):
                findings.append(
                    Finding(
                        severity=Severity.NOTE,
                        path=path,
                        message=f"{reference.described()} was not verified",
                        remedy=(
                            "resolving it would run a command, which an audit "
                            "does not do. Pass resolve=True if this config is "
                            "yours and you want it checked"
                        ),
                    )
                )
            elif not reference.is_resolvable():
                findings.append(
                    Finding(
                        severity=Severity.NOTE,
                        path=path,
                        message=f"{reference.described()} resolves to nothing",
                        remedy='set it, or add "required": false if it is optional',
                    )
                )
        return findings

    def _literal_findings(self) -> list[Finding]:
        """Plain strings that hold a secret.

        Two independent checks, because each catches what the other misses.
        A published credential format is recognized from the value, whatever
        the key is called — which is the case key names cannot cover, since
        nothing stops a live key sitting under `tracking.ref`. A
        secret-looking key name catches the rest: an internal password has no
        published shape to match.
        """
        findings = []
        for path, value in Tree.strings(self._config.data):
            if identified := KnownFormat.identify(value):
                findings.append(self._known_format_finding(path, identified))
            elif self._looks_like_a_secret(path, value):
                findings.append(self._literal_finding(path, value))
        return findings

    @staticmethod
    def _looks_like_a_secret(path: str, value: str) -> bool:
        """Whether a key name suggests a credential and the value could be one."""
        if not SecretKey.matches(path):
            return False
        return not (Placeholder.too_short_to_judge(value) or Placeholder.matches(value))

    def _known_format_finding(self, path: str, identified: str) -> Finding:
        """One credential matching a published format.

        Always an error, and always regardless of the key name or whether a
        repository was found. A value matching an issuer's published shape is
        a real credential — there is no reading of it as a placeholder, and
        the right response is to rotate it rather than to move it.
        """
        inside = (
            " inside a repository, so git history keeps it"
            if self._repository is not None
            else " in a config file"
        )
        return Finding(
            severity=Severity.ERROR,
            path=path,
            message=f"{identified}{inside}",
            remedy=(
                "rotate this credential, then reference it instead of storing "
                'it: {"env": "YOUR_VAR"}'
            ),
        )

    def _literal_finding(self, path: str, value: str) -> Finding:
        """One literal, with a severity that depends on the repository."""
        if Placeholder.is_noise(value):
            return Finding(
                severity=Severity.NOTE,
                path=path,
                message="a literal value, which looks like a placeholder",
                remedy="replace it with a reference before deploying",
            )
        if self._repository is not None:
            return Finding(
                severity=Severity.ERROR,
                path=path,
                message="a literal secret inside a repository",
                remedy=(
                    "move it to an environment variable and reference it: "
                    '{"env": "YOUR_VAR"} — and rotate it, since git history '
                    "keeps the old value"
                ),
            )
        return Finding(
            severity=Severity.WARNING,
            path=path,
            message="a literal secret in a config file",
            remedy='reference it instead of storing it: {"env": "YOUR_VAR"}',
        )
