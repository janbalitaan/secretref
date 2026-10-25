# Examples

Runnable files, in the order worth reading them. Each one is self-contained
and prints what it did.

```bash
python examples/01_reading_a_config.py
```

| | |
| --- | --- |
| [`01_reading_a_config.py`](01_reading_a_config.py) | Reading values and references, and what required / optional / default do. |
| [`02_auditing_in_ci.py`](02_auditing_in_ci.py) | The audit, which is what the library is for. |
| [`03_auditing_is_safe.py`](03_auditing_is_safe.py) | Why auditing a pull request runs none of its commands. |
| [`04_policies.py`](04_policies.py) | Bounding what a config may reach, and the defaults. |
| [`05_a_startup_check.py`](05_a_startup_check.py) | Failing a deployment rather than a request. |
| [`06_extending.py`](06_extending.py) | Auditing for a format this version has never heard of. |

Every file is run by the test suite, so an example that stops working fails
CI rather than sitting here misleading someone.

For the reasoning behind any of it, see [`../docs/`](../docs/README.md).
