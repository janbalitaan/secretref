"""The settings each policy holds, as immutable snapshots.

One per reference form, each in its own file. They are frozen and swapped
whole rather than mutated, so a reader never sees a half-applied policy — the
reasoning is in each module.
"""

from __future__ import annotations

from secretref.policies.settings.command import CommandSettings
from secretref.policies.settings.environment import EnvironmentSettings
from secretref.policies.settings.file import FileSettings

__all__ = ["CommandSettings", "EnvironmentSettings", "FileSettings"]
