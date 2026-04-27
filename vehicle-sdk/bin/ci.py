#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = PROJECT_ROOT / "openocc"
MIN_COVERAGE = 80


def run(cmd):
    print(f"\n>>> Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main():
    # Clean old coverage data
    run(["coverage", "erase"])

    # Run tests with coverage
    run(["coverage", "run", f"--source={SRC_DIR}", "-m", "unittest"])

    # Generate HTML report (useful artifact in CI)
    run(["coverage", "html"])

    # Print coverage report
    run(["coverage", "report", f"--fail-under={MIN_COVERAGE}"])

    print("\n✅ CI checks passed.")


if __name__ == "__main__":
    main()
