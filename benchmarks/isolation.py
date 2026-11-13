"""A safety interlock, not a sandbox. Use a disposable, offline container/VM.

Never mount host system configuration or user data into the benchmark container.
"""

import os
from pathlib import Path


def require_isolated_container():
    if (
        os.name != "posix"
        or not Path("/.dockerenv").is_file()
        or os.environ.get("FSTEC_BENCHMARK_DISPOSABLE") != "1"
    ):
        raise RuntimeError(
            "external shell benchmarks require an explicitly disposable Docker container"
        )
