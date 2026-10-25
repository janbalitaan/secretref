"""Every expression this library matches, named.

The audit is a policy — which key names suggest a credential, which values are
obviously filler. Keeping the expressions here and the policy in `audit.py`
means each file has one job: this is the list of *what* is recognized, and
that is the list of what happens when something is.

These are also the most likely thing a contributor edits. A key name the audit
misses, or a placeholder form it mistakes for a real secret, is a one-line
change to this file and a test beside it.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Key names
# ---------------------------------------------------------------------------

# Matched against the final segment of a dotted path, so
# "providers.0.api_key" is checked as "api_key".
SECRET_KEY = re.compile(
    r"(?i)(?:^|_)(?:secret|password|passwd|pwd|token|api_?key|key|credential|"
    r"auth|access_?key|private_?key|client_?secret|dsn|connection_?string)$"
)


# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------
#
# Generous on purpose. A false negative here costs one spurious error, while a
# false positive reports a real secret as filler and hides it — so a value has
# to look quite deliberately like a placeholder to be treated as one.

PLACEHOLDERS: tuple[re.Pattern[str], ...] = (
    # Anything addressed to the reader: "your-api-key", "my_token_here".
    re.compile(r"(?i)^(?:your|my|our|the)[-_ ]"),
    # Anything announcing itself as filler, anywhere in the value.
    re.compile(
        r"(?i)(?:^|[-_ ])(?:xxx+|todo|tbd|fixme|changeme|change[-_ ]me|"
        r"placeholder|example|sample|dummy|fake|replace[-_ ]?me|insert|"
        r"goes[-_ ]here|here)(?:$|[-_ ])"
    ),
    # Template syntax left unfilled: <KEY>, {{KEY}}, ${KEY}, %KEY%.
    re.compile(r"^(?:<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|%[^%]*%)$"),
    # Another tool's interpolation, which is a reference and not a value.
    # A config is often read by something else as well — a settings library,
    # a templating layer, a hierarchical merger — and reporting its syntax as
    # a hardcoded secret is the fastest way to have an audit ignored.
    re.compile(r"(?i)^@(?:format|jinja|json|int|float|bool|none|empty|get)\b"),
    re.compile(r"\{\{.*\}\}|\$\{.*\}|\{env\[[^\]]+\]\}|%\([^)]+\)s"),
    # Only punctuation, or one character repeated.
    re.compile(r"^(?:\.{2,}|-{2,}|_{2,}|\*{2,})$"),
    re.compile(r"^(.)\1{7,}$"),
)


# ---------------------------------------------------------------------------
# Known credential formats
# ---------------------------------------------------------------------------
#
# Issuers publish the shape of their credentials, which makes these the one
# kind of secret that can be recognized from the value alone — no key name
# and no entropy guess. That matters because the key name is exactly what an
# audit cannot rely on: a live key under `wandb.api_key` is found by either
# method, while the same key under `tracking.id` is found only by this one.
#
# Each entry is (name, pattern). The name goes into the finding, so a reader
# knows what to rotate and where. The first match wins, so a narrower pattern
# comes before a wider one it would otherwise be swallowed by — "sk-ant-"
# before the general "sk-" form.
KNOWN_SECRET_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("an AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("a GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{70,}\b")),
    ("a Stripe secret key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("a Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("a Google API key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("an Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    # Narrow deliberately. A loose "sk-" rule claims anything beginning that
    # way, and plenty of made-up or internal values do — a wrong name on a
    # finding is worse than a generic one, because it sends someone to rotate
    # a key at a provider they do not use.
    ("an OpenAI project key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{32,}\b")),
    ("an OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("a SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
    ("a Twilio account SID", re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("a npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("a PyPI API token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("a HashiCorp Vault token", re.compile(r"\bhv[sb]\.[A-Za-z0-9_-]{24,}\b")),
    ("a private key block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("a JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
    (
        "a database connection string with a password",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:/@\s]+:[^@/\s]{4,}@"
        ),
    ),
)
