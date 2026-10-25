"""Bounding what a config file is allowed to reach.

The defaults are chosen so the ordinary deployments configure nothing:
environment variables, Docker, Kubernetes and systemd all need zero lines.

    python examples/04_policies.py
"""

from secretref import CommandPolicy, EnvironmentPolicy, FilePolicy

print("what you get if you configure nothing:")
for policy in (CommandPolicy(), FilePolicy(), EnvironmentPolicy()):
    print(f"  {policy.describe()}")

print()
print("commands are off because a config that can name one can name any:")
CommandPolicy().allow("op")  # just the 1Password CLI
print(f"  {CommandPolicy().describe()}")

print()
print("and the executable is pinned when you allow it, not when it is used,")
print("so a later change to PATH cannot substitute a different binary.")

print()
print("files are confined to where secrets are actually mounted:")
print(f"  {FilePolicy().describe()}")
FilePolicy().restrict("./secrets", require_private=False)
print(f"  on a laptop: {FilePolicy().describe()}")

print()
print("environment references are open, because a process can already read")
print("its own environment. Narrow them when a config is rendered into output:")
EnvironmentPolicy().restrict(prefixes=["MYAPP_"])
print(f"  {EnvironmentPolicy().describe()}")
print(f"  permits MYAPP_TOKEN:          {EnvironmentPolicy().permits('MYAPP_TOKEN')}")
print(
    f"  permits AWS_SECRET_ACCESS_KEY: {EnvironmentPolicy().permits('AWS_SECRET_ACCESS_KEY')}"
)

# Policies are process-wide singletons, so reset what this example changed.
CommandPolicy().forbid()
FilePolicy().reset()
EnvironmentPolicy().relax()
