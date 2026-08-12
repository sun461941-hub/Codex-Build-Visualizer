from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


SKILL = Path(__file__).resolve().parents[1]
PACKAGER = SKILL / "scripts" / "package_plugin.py"


def load_packager():
    spec = importlib.util.spec_from_file_location("codex_build_packager", PACKAGER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DistributionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-build-distribution-test.")
        self.base = Path(self.temporary.name)
        self.packager = load_packager()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, name: str, mode: str = "plugin", version: str = "1.2.3") -> Path:
        output = self.base / name
        self.packager.build_archive(
            mode=mode,
            version=version,
            output=output,
            skill_root=SKILL,
        )
        return output

    @staticmethod
    def names(archive: zipfile.ZipFile) -> list[str]:
        return [entry.filename for entry in archive.infolist()]

    def assert_deterministic_metadata(self, archive: zipfile.ZipFile) -> None:
        names = self.names(archive)
        self.assertEqual(names, sorted(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(archive.comment, b"")
        for entry in archive.infolist():
            self.assertEqual(entry.date_time, self.packager.FIXED_ZIP_TIME)
            self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
            self.assertEqual(entry.create_system, 3)
            mode = entry.external_attr >> 16
            self.assertTrue(stat.S_ISREG(mode), entry.filename)
            self.assertEqual(stat.S_IMODE(mode), 0o644, entry.filename)
            self.assertEqual(entry.extra, b"")
            self.assertEqual(entry.comment, b"")

    def test_plugin_builds_are_identical_and_exactly_allowlisted(self) -> None:
        first = self.build("plugin-a.zip")
        second = self.build("plugin-b.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).hexdigest(),
            hashlib.sha256(second.read_bytes()).hexdigest(),
        )

        expected = {
            ".codex-plugin/plugin.json",
            "skills/codex-build-visualizer/SKILL.md",
            "skills/codex-build-visualizer/agents/openai.yaml",
            "skills/codex-build-visualizer/assets/icon.svg",
            "skills/codex-build-visualizer/assets/viewer.html",
            "skills/codex-build-visualizer/scripts/trace.py",
        }
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(set(self.names(archive)), expected)
            self.assert_deterministic_metadata(archive)
            manifest = json.loads(archive.read(".codex-plugin/plugin.json"))
            self.assertEqual(manifest["name"], "codex-build-visualizer")
            self.assertEqual(manifest["version"], "1.2.3")
            self.assertEqual(manifest["skills"], "./skills/")
            for invented in ("author", "license", "repository", "homepage"):
                self.assertNotIn(invented, manifest)
            packaged_skill = archive.read("skills/codex-build-visualizer/SKILL.md").decode("utf-8")
            self.assertNotIn("references/distribution.md", packaged_skill)
            self.assertNotIn("scripts/package_plugin.py", packaged_skill)

        joined = "\n".join(sorted(expected)).lower()
        for forbidden in (
            ".codex-visualizer",
            "__pycache__",
            ".pyc",
            ".git/",
            "trace.json",
            "events.js",
            "meta.js",
        ):
            self.assertNotIn(forbidden, joined)

    def test_repository_builds_are_identical_and_cross_platform_ready(self) -> None:
        first = self.build("repo-a.zip", mode="repo", version="2.0.0-rc.1")
        second = self.build("repo-b.zip", mode="repo", version="2.0.0-rc.1")
        self.assertEqual(first.read_bytes(), second.read_bytes())

        plugin_prefix = "plugins/codex-build-visualizer/"
        skill_prefix = plugin_prefix + "skills/codex-build-visualizer/"
        expected_runtime = {skill_prefix + relative for relative in self.packager.RUNTIME_FILES}
        with zipfile.ZipFile(first) as archive:
            names = set(self.names(archive))
            self.assert_deterministic_metadata(archive)
            self.assertTrue(expected_runtime.issubset(names))
            self.assertIn(plugin_prefix + ".codex-plugin/plugin.json", names)
            self.assertIn(".agents/plugins/marketplace.json", names)
            self.assertIn(".github/workflows/test.yml", names)
            self.assertIn("scripts/package_plugin.py", names)
            self.assertIn("tests/test_trace.py", names)
            self.assertIn("tests/test_viewer.py", names)
            self.assertIn("tests/test_browser.py", names)
            self.assertIn("tests/test_distribution.py", names)
            self.assertIn("tests/run_repo_tests.py", names)
            self.assertIn("docs/distribution.md", names)

            packaged_skill = {
                name for name in names
                if name.startswith(skill_prefix)
            }
            self.assertEqual(packaged_skill, expected_runtime)
            marketplace = json.loads(archive.read(".agents/plugins/marketplace.json"))
            entry = marketplace["plugins"][0]
            self.assertEqual(entry["source"]["source"], "local")
            self.assertEqual(
                entry["source"]["path"],
                "./plugins/codex-build-visualizer",
            )
            workflow = archive.read(".github/workflows/test.yml").decode("utf-8")
            for runner in ("ubuntu-latest", "macos-latest", "windows-latest"):
                self.assertIn(runner, workflow)
            self.assertIn('python: ["3.9", "3.12"]', workflow)
            self.assertIn("permissions:\n  contents: read", workflow)
            self.assertIn(
                "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                workflow,
            )
            self.assertIn(
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
                workflow,
            )
            self.assertIn(
                "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
                workflow,
            )
            self.assertIn("playwright@1.62.0", workflow)
            self.assertIn("jsdom@26.1.0", workflow)
            self.assertIn("playwright install --with-deps chromium", workflow)
            self.assertIn("tests/run_repo_tests.py test_browser", workflow)
            self.assertIn('CBV_REQUIRE_BROWSER: "1"', workflow)
            runner = archive.read("tests/run_repo_tests.py").decode("utf-8")
            self.assertIn('environment["NODE_PATH"]', runner)
            self.assertIn('REPOSITORY / "node_modules"', runner)
            self.assertIn('str(stage / "tests")', runner)
            self.assertIn('["tests.test_viewer", "tests.test_browser", "-v"]', runner)
            self.assertNotIn('str(REPOSITORY / "tests"), "-v"', runner)
            self.assertNotIn("uses: actions/checkout@v", workflow)
            self.assertNotIn("uses: actions/setup-python@v", workflow)
            self.assertNotIn("uses: actions/setup-node@v", workflow)

        lowered = "\n".join(sorted(names)).lower()
        for forbidden in (".codex-visualizer", "__pycache__", ".pyc", ".git/"):
            self.assertNotIn(forbidden, lowered)

    def test_generated_repository_runner_executes_against_staged_skill(self) -> None:
        archive_path = self.build("repo-runner.zip", mode="repo")
        extracted = self.base / "extracted-repository"
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(extracted)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(extracted / "tests" / "run_repo_tests.py"),
                "tests.test_distribution.DistributionTests.test_semver_is_strict",
            ],
            cwd=extracted,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_semver_is_strict(self) -> None:
        for valid in ("0.0.0", "1.2.3", "1.0.0-alpha.1", "1.0.0+build.7"):
            with self.subTest(valid=valid):
                self.assertEqual(self.packager.validate_version(valid), valid)
        for invalid in (
            "1",
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.0.0-01",
            "v1.2.3",
            "1.2.3/../../escape",
            "1.2.3\nnext",
            "1.2.3-",
            "1.2.3+",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.packager.PackagingError):
                    self.packager.validate_version(invalid)

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.build("existing.zip")
        before = output.read_bytes()
        with self.assertRaises(self.packager.PackagingError):
            self.packager.build_archive(
                mode="plugin",
                version="1.2.4",
                output=output,
                skill_root=SKILL,
            )
        self.assertEqual(output.read_bytes(), before)

    def make_source_copy(self) -> Path:
        root = self.base / "source-copy"
        for relative in self.packager.RUNTIME_FILES + self.packager.REPOSITORY_FILES:
            source = SKILL.joinpath(*relative.split("/"))
            destination = root.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return root

    def test_link_and_nonregular_sources_are_rejected(self) -> None:
        root = self.make_source_copy()
        icon = root / "assets" / "icon.svg"
        icon.unlink()
        try:
            icon.symlink_to(root / "SKILL.md")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation is unavailable: {error}")
        with self.assertRaises(self.packager.PackagingError):
            self.packager.collect_entries(root, "plugin", "1.0.0")

        icon.unlink()
        icon.mkdir()
        with self.assertRaises(self.packager.PackagingError):
            self.packager.collect_entries(root, "plugin", "1.0.0")

    @unittest.skipIf(os.name == "nt", "POSIX descriptor traversal")
    def test_pinned_root_rejects_swapped_parent_symlink(self) -> None:
        root = self.make_source_copy()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "icon.svg").write_text("OUTSIDE_SECRET", encoding="utf-8")
        descriptor = self.packager._open_posix_directory(root)
        try:
            (root / "assets").rename(root / "assets-original")
            (root / "assets").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(self.packager.PackagingError):
                self.packager._read_regular_file(
                    root, "assets/icon.svg", root_descriptor=descriptor,
                )
        finally:
            os.close(descriptor)

    def test_link_output_parent_is_rejected(self) -> None:
        real = self.base / "real-output"
        real.mkdir()
        linked = self.base / "linked-output"
        try:
            linked.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation is unavailable: {error}")
        with self.assertRaises(self.packager.PackagingError):
            self.packager.build_archive(
                mode="plugin",
                version="1.0.0",
                output=linked / "plugin.zip",
                skill_root=SKILL,
            )

    def test_cli_reports_digest_and_refuses_bad_version(self) -> None:
        output = self.base / "cli.zip"
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(PACKAGER),
                "--mode",
                "plugin",
                "--version",
                "3.4.5",
                "--output",
                str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        self.assertIn("sha256:", result.stdout)
        self.assertIn(hashlib.sha256(output.read_bytes()).hexdigest(), result.stdout)

        bad = subprocess.run(
            [
                sys.executable,
                "-B",
                str(PACKAGER),
                "--mode",
                "plugin",
                "--version",
                "1.0",
                "--output",
                str(self.base / "bad.zip"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(bad.returncode, 2)
        self.assertIn("SemVer", bad.stderr)
        self.assertFalse((self.base / "bad.zip").exists())


if __name__ == "__main__":
    unittest.main()
