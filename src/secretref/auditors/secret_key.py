"""Whether a config path names a credential."""

from __future__ import annotations

import re
from typing import ClassVar

from secretref.patterns import SECRET_KEY


class SecretKey:
    """Whether a config path names a credential."""

    PATTERN: ClassVar[re.Pattern[str]] = SECRET_KEY

    @classmethod
    def matches(cls, dotted: str) -> bool:
        """Whether a path's final segment names a credential.

        Only the final segment, so "providers.0.api_key" is judged on
        "api_key". A parent path saying "providers" tells you nothing about
        whether this particular leaf holds a secret.
        """
        last = dotted.rsplit(".", 1)[-1]
        return bool(cls.PATTERN.search(last))
