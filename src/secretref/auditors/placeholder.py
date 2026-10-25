"""Whether a value is filler rather than a real secret."""

from __future__ import annotations

import re
from typing import ClassVar

from secretref.constants import MIN_SECRET_LENGTH
from secretref.patterns import PLACEHOLDERS


class Placeholder:
    """Whether a value is filler rather than a real secret."""

    PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = PLACEHOLDERS

    @classmethod
    def matches(cls, value: str, patterns: tuple[re.Pattern[str], ...] | None = None) -> bool:
        """Whether a value is obviously filler.

        Generous on purpose. A false negative here costs one spurious error,
        which a reader dismisses. A false positive reports a real secret as
        filler and hides it, which is the failure that matters.
        """
        candidate = value.strip()
        chosen = patterns if patterns is not None else cls.PATTERNS
        return any(pattern.search(candidate) for pattern in chosen)

    @classmethod
    def too_short_to_judge(cls, value: str, minimum: int | None = None) -> bool:
        """Whether a value is too short to be worth reporting.

        A short string under a secret-looking key is more often a flag or an
        abbreviation than a credential, and reporting those is how an audit
        trains people to ignore it.
        """
        return len(value.strip()) < (MIN_SECRET_LENGTH if minimum is None else minimum)

    @classmethod
    def is_noise(
        cls,
        value: str,
        patterns: tuple[re.Pattern[str], ...] | None = None,
        minimum: int | None = None,
    ) -> bool:
        """Whether a value should be a note rather than an error."""
        return cls.matches(value, patterns) or cls.too_short_to_judge(value, minimum)
