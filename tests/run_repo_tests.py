"""Stage the packaged skill and run its maintainer tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[1]
PACKAGED_SKILL = (
    REPOSITORY / "plugins" / "codex-build-visualizer" / "skills"
    / "codex-build-visualizer"
)


def main() -> int:
    modules = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="codex-build-visualizer-ci.") as temporary:
        stage = Path(temporary) / "codex-build-visualizer"
        shutil.copytree(PACKAGED_SKILL, stage)
        shutil.copytree(REPOSITORY / "tests", stage / "tests")
        (stage / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            REPOSITORY / "scripts" / "package_plugin.py",
            stage / "scripts" / "package_plugin.py",
        )
        (stage / "references").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            REPOSITORY / "docs" / "distribution.md",
            stage / "references" / "distribution.md",
        )
        arguments = [sys.executable, "-B", "-m", "unittest"]
        if modules == ["test_browser"]:
            arguments.extend(["tests.test_viewer", "tests.test_browser", "-v"])
        elif not modules:
            arguments.extend(["discover", "-s", str(stage / "tests"), "-v"])
        else:
            arguments.extend(modules)
        environment = os.environ.copy()
        repository_modules = str(REPOSITORY / "node_modules")
        environment["NODE_PATH"] = repository_modules + (
            os.pathsep + environment["NODE_PATH"]
            if environment.get("NODE_PATH") else ""
        )
        return subprocess.call(arguments, cwd=stage, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())
