#!/usr/bin/env python3
"""M0 candidate: hard-inactive independently of the GitHub job gate.

No imports of os, subprocess, provider clients, filesystem APIs or secret
readers. This is the actual source-bound native entry, not a mock executor.
The first slice cannot inspect protected inputs or start any child process.
"""
from __future__ import annotations

import sys

EXIT_INACTIVE = 78
CLOSED_RESULT = '{"kind":"envs.mailM0.manual.v1","status":"INACTIVE","effect":"NOT_RUN"}'


def main() -> int:
    # This unconditional refusal is intentionally before any argument or
    # environment evaluation. There is NO activation flag/escape path.
    print(CLOSED_RESULT)
    return EXIT_INACTIVE


if __name__ == "__main__":
    sys.exit(main())
