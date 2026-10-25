"""The names and limits this library uses.

Collected here so the conventions a project has to follow are readable in one
place rather than discovered from a stack trace.
"""

from __future__ import annotations

# Config filenames looked for, in order of preference.
CONFIG_NAMES: tuple[str, ...] = (
    "config.json",
    ".config.json",
    "settings.json",
    "config.yaml",
    "config.yml",
)

# Keys that mark a value as a reference rather than a literal.
ENV_KEY = "env"
FILE_KEY = "file"
COMMAND_KEY = "command"
LITERAL_KEY = "literal"
DEFAULT_KEY = "default"
REQUIRED_KEY = "required"

# The keys that mean indirection: the value lives somewhere else.
REFERENCE_KEYS: frozenset[str] = frozenset({ENV_KEY, FILE_KEY, COMMAND_KEY})

# What marks a mapping as a secret at all, for discovery.
#
# `literal` has to be in here even though it is not indirection. Without it,
# {"literal": "sk-live-..."} is invisible to the audit: `secrets()` does not
# recognize the mapping, and the string walk sees the path as
# "api_key.literal" whose last segment is "literal" rather than a name that
# suggests a credential. The one form that explicitly declares an inline
# secret would be the one form nothing reports.
SECRET_KEYS: frozenset[str] = REFERENCE_KEYS | {LITERAL_KEY}

# What a resolved secret is replaced with in any human-readable output.
REDACTED = "[redacted]"

# How a config with no filename is named in a message — one loaded from a
# string has nothing better to call itself. Shared so the four messages that
# need it cannot drift into saying three different things.
UNNAMED_CONFIG = "the config"

# A value shorter than this is unlikely to be a real credential, so the audit
# does not warn about it — it is more often a placeholder or a short flag.
MIN_SECRET_LENGTH = 8

# Markers that a directory is a working copy. A literal secret inside one is
# a commit away from being published, which is what the audit exists to stop.
REPOSITORY_MARKERS: tuple[str, ...] = (".git", ".hg", ".svn")

# How far up the tree to look for a repository marker before giving up.
MAX_PARENTS_SEARCHED = 40

# Seconds a command reference may take before it is abandoned.
COMMAND_TIMEOUT_SECONDS = 10

# Bytes of output a command reference may produce. A secret is short; a
# command that produces more than this is either the wrong command or an
# attempt to exhaust memory, and neither is worth reading to the end.
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024

# Environment variables a command reference inherits when the caller names
# none. Deliberately almost nothing: a subprocess given the parent's whole
# environment can read every other secret the process holds, which defeats
# the point of resolving them one at a time.
#
# PATH and HOME are here because most secret-manager CLIs will not start
# without them — `op`, `vault` and `aws` all read config from under HOME.
MINIMAL_ENVIRONMENT: tuple[str, ...] = ("PATH", "HOME", "LANG", "TMPDIR")

# Where secrets are mounted by the things that actually mount secrets, used
# as the default roots when a caller turns on root checking but names none.
#
# Deliberately short. Every entry here widens what a file reference may read,
# so a path belongs only if a real tool documents putting secrets there:
#
#   /run/secrets        Docker Compose and Swarm mount secrets here
#   /run/credentials    systemd LoadCredential, as /run/credentials/<unit>
#
# /var/run/secrets is not listed because /var/run is a symlink to /run on
# any modern Linux, so it resolves to an entry already present — and the
# check compares resolved paths. Kubernetes mounts under
# /var/run/secrets/kubernetes.io, which lands inside /run/secrets after
# resolution.
#
# Anything else is for the caller to name. A default allowlist that guesses
# is a default allowlist that reads somewhere it should not.
SECRET_MOUNTS: tuple[str, ...] = (
    "/run/secrets",
    "/run/credentials",
)

# Permission bits that mean someone other than the owner can read a file.
# A secret readable by group or world is a finding whether or not anything
# has read it yet.
GROUP_AND_WORLD_READABLE = 0o077

# Bytes a secret file may hold. Generous for a credential and small enough
# that pointing a reference at a log file fails rather than exhausting memory.
MAX_SECRET_FILE_BYTES = 64 * 1024
