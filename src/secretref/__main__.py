"""Lets the tool run as `python -m secretref`, not only as `secretref`.

Useful when the package is installed somewhere the console script is not on
PATH, which is common in a container.
"""

from __future__ import annotations

from secretref.cli import run

run()
