#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = PROJECT_ROOT / "steering_wheel"
MIN_COVERAGE = 80


def run(cmd, cwd):
    print(f"\n>>> Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main():
    # Clean old coverage data
    run(["coverage", "erase"], cwd=PROJECT_ROOT)

    # Run tests with coverage
    run(["coverage", "run", f"--source={SRC_DIR}", "-m", "unittest"], cwd=PROJECT_ROOT)

    # Generate HTML report (useful artifact in CI)
    run(["coverage", "html"], cwd=PROJECT_ROOT)

    # Print coverage report
    run(["coverage", "report", f"--fail-under={MIN_COVERAGE}"], cwd=PROJECT_ROOT)

    print("\n✅ CI checks passed.")


if __name__ == "__main__":
    main()
