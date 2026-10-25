"""What the audit looks for, as data a caller can change."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
import re

from secretref.constants import MIN_SECRET_LENGTH, REPOSITORY_MARKERS
from secretref.exceptions import ConfigError
from secretref.patterns import KNOWN_SECRET_FORMATS, PLACEHOLDERS, SECRET_KEY

# An inline case-insensitivity flag at the start of a pattern, which has to be
# removed before the pattern can be nested inside another.
_INLINE_IGNORECASE = re.compile(r"^\(\?i\)")


@dataclass(frozen=True)
class Rules:
    r"""The patterns the audit judges a config by.

    These were constants, which made them adjustable only by editing the
    installed package. That put every new credential format on this library's
    release cycle — and the realistic reasons to change one are immediate: a
    vendor publishes a format nobody has covered, a shipped pattern fires on
    something harmless in one codebase, a team names its credential keys
    something the key-name rule does not recognize.

    Frozen, and every adjustment returns a new set. A `Rules` passed to
    `audit()` is read concurrently by nothing, but a shared mutable policy is
    the bug class this library has already been bitten by once.

        rules = Rules.default().with_formats(
            {"a Fastly API token": re.compile(r"\\b[A-Za-z0-9_-]{32}\\b")}
        )
        audit(config, rules=rules)
    """

    formats: tuple[tuple[str, re.Pattern[str]], ...] = KNOWN_SECRET_FORMATS
    secret_key: re.Pattern[str] = SECRET_KEY
    placeholders: tuple[re.Pattern[str], ...] = PLACEHOLDERS
    min_secret_length: int = MIN_SECRET_LENGTH
    repository_markers: tuple[str, ...] = REPOSITORY_MARKERS
    extra_key_names: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def default(cls) -> Rules:
        """Return the shipped rules, as a starting point to adjust."""
        return cls()

    def with_formats(
        self,
        add: Mapping[str, re.Pattern[str]] | None = None,
        *,
        replace_named: Mapping[str, re.Pattern[str]] | None = None,
        without: Iterable[str] | None = None,
    ) -> Rules:
        """Return rules with the credential formats adjusted.

        `add` appends, which is right for a vendor the shipped list does not
        cover. `replace_named` swaps a pattern while keeping its position,
        because the first match wins and the order places narrower patterns
        before wider ones. `without` drops a format that misfires here.

        A name in `replace_named` or `without` that is not present raises:
        the usual cause is a typo, and silently doing nothing would leave a
        caller believing a format was changed when it was not.
        """
        swaps = dict(replace_named or {})
        removals = set(without or ())
        self._check_names(swaps, removals)

        kept = tuple(
            (name, swaps.get(name, pattern))
            for name, pattern in self.formats
            if name not in removals
        )
        return replace(self, formats=kept + tuple((add or {}).items()))

    def with_secret_keys(self, names: Iterable[str]) -> Rules:
        """Return rules that also treat these key names as credential-shaped.

        For a team whose convention the shipped rule does not know —
        `access_pass`, `shared_secret_v2`, `signing_material`. Matched
        against the final segment of a dotted path, case-insensitively, and
        word-bounded so `api_key_id` is not caught by `api_key`.

        Extends rather than replaces, because a caller adding one name almost
        never means "and stop recognizing password". To replace the rule
        outright, construct `Rules(secret_key=...)`.
        """
        extra = frozenset(name.strip().lower() for name in names if name and name.strip())
        if not extra:
            return self
        combined = self.extra_key_names | extra
        alternation = "|".join(re.escape(name) for name in sorted(combined))
        # The shipped pattern carries an inline `(?i)`, and an inline flag has
        # to be the first thing in an expression — nesting it inside `(?:...)`
        # raises "global flags not at the start". So it is stripped and the
        # flag passed as an argument, which is equivalent and composes.
        base = _INLINE_IGNORECASE.sub("", self.secret_key.pattern, count=1)
        return replace(
            self,
            extra_key_names=combined,
            secret_key=re.compile(
                f"(?:{base})|(?:^|_)(?:{alternation})$",
                self.secret_key.flags | re.IGNORECASE,
            ),
        )

    def with_placeholders(self, patterns: Iterable[str | re.Pattern[str]]) -> Rules:
        """Return rules that also treat these shapes as filler.

        For a codebase with its own convention for "not filled in yet" —
        `__REPLACE__`, `<<set-by-terraform>>`. A value matching one is
        reported as a note rather than an error.

        A pattern that will not compile raises here, naming it, rather than
        at match time when the caller has no idea which entry was wrong.
        """
        compiled = []
        for pattern in patterns:
            if isinstance(pattern, re.Pattern):
                compiled.append(pattern)
                continue
            try:
                compiled.append(re.compile(pattern))
            except re.error as error:
                raise ConfigError(
                    f"placeholder pattern {pattern!r} does not compile: {error}"
                ) from error
        return replace(self, placeholders=self.placeholders + tuple(compiled))

    def with_repository_markers(self, markers: Iterable[str]) -> Rules:
        """Return rules that recognize these as version control roots.

        The severity of a finding turns on this. A literal secret inside a
        working copy is one commit from a remote and git history keeps it
        after the fix; the same value outside one is careless but contained.
        So a repository this version does not recognize — `.jj`, `.fossil`,
        `.bzr` — means real findings reported one level too quietly.

        Replaces rather than extends, because a caller naming their markers
        knows which ones apply. Pass `(*REPOSITORY_MARKERS, ".jj")` to add.
        """
        chosen = tuple(marker for marker in markers if marker)
        if not chosen:
            raise ConfigError(
                "at least one repository marker is needed; with none, every "
                "literal secret would be reported as outside a repository"
            )
        return replace(self, repository_markers=chosen)

    def with_minimum_length(self, length: int) -> Rules:
        """Return rules with a different bar for "too short to judge".

        Below it, a value under a credential-shaped key is reported as a note
        rather than an error — a short string there is more often a flag or an
        abbreviation than a secret. Raise it for a codebase full of short
        enum values; lower it if real short secrets are getting through.
        """
        if length < 1:
            raise ConfigError(
                f"the minimum secret length must be at least 1 (got {length}); "
                "0 would treat an empty value as a secret"
            )
        return replace(self, min_secret_length=length)

    def describe(self) -> str:
        """Summarize the rules, for a line that is safe to log."""
        added = f", {len(self.extra_key_names)} extra key names" if self.extra_key_names else ""
        return (
            f"audit rules: {len(self.formats)} credential formats, "
            f"{len(self.placeholders)} placeholder shapes, "
            f"values under {self.min_secret_length} characters are notes{added}"
        )

    def _check_names(self, swaps: Mapping[str, re.Pattern[str]], removals: set[str]) -> None:
        """Raise when a named format is not in this set, listing what is."""
        available = {name for name, _ in self.formats}
        for operation, names in (("replace_named", set(swaps)), ("without", removals)):
            unknown = sorted(names - available)
            if not unknown:
                continue
            raise ConfigError(
                f"{operation} names a credential format that is not in these "
                f"rules: {', '.join(unknown)}. Available formats are: "
                f"{', '.join(sorted(available))}"
            )
