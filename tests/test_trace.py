from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SKILL = Path(__file__).resolve().parents[1]
TRACE = SKILL / "scripts" / "trace.py"


def load_module():
    spec = importlib.util.spec_from_file_location("codex_build_trace", TRACE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-build-visualizer-test.")
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        # Detached automatic-snapshot workers can be in the final public-artifact
        # fsync after the checkpoint already reports completion. Give that narrow
        # window time to close so cleanup does not become a flaky race.
        error: OSError | None = None
        for _ in range(20):
            try:
                self.temporary.cleanup()
                return
            except OSError as exc:
                error = exc
                time.sleep(.05)
        if error is not None:
            raise error

    def run_trace(
        self, *arguments: object, input_bytes: bytes | None = None,
        expected: int | set[int] = 0, timeout: float = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        allowed = {expected} if isinstance(expected, int) else expected
        result = subprocess.run(
            [sys.executable, "-B", str(TRACE), *(str(value) for value in arguments)],
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        self.assertIn(
            result.returncode, allowed,
            f"stdout={result.stdout.decode(errors='replace')!r}\nstderr={result.stderr.decode(errors='replace')!r}",
        )
        return result

    def initialize(self, name: str = "project", privacy: str = "standard") -> Path:
        root = self.base / name
        root.mkdir(parents=True, exist_ok=True)
        self.run_trace("init", "--root", root, "--title", name, "--privacy", privacy, "--lang", "en")
        return root

    @staticmethod
    def state(root: Path) -> dict:
        return json.loads((root / ".codex-visualizer" / "trace.json").read_text(encoding="utf-8"))

    @staticmethod
    def public(root: Path) -> dict:
        raw = (root / ".codex-visualizer" / "events.js").read_text(encoding="utf-8")
        payload = raw.removeprefix("window.CODEX_BUILD_TRACE=").split(";if(window.__codexTraceReceive)", 1)[0]
        return json.loads(payload)

    def test_basic_workflow_and_owner_only_modes(self) -> None:
        root = self.initialize()
        self.run_trace("plan", "--root", root, "--id", "one", "--title", "Implement", "--status", "completed")
        self.run_trace("event", "--root", root, "--title", "Done")
        self.run_trace("finish", "--root", root, "--status", "completed", "--summary", "Complete")
        state = self.state(root)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["plan"][0]["status"], "completed")
        if os.name != "nt":
            trace = root / ".codex-visualizer"
            self.assertEqual(trace.stat().st_mode & 0o777, 0o700)
            for name in (".trace.lock", ".gitignore", "trace.json", "events.js", "index.html"):
                self.assertEqual((trace / name).stat().st_mode & 0o777, 0o600)

    def test_strict_public_state_is_anonymized_and_aliases_are_stable(self) -> None:
        root = self.initialize(privacy="strict")
        secret_file = root / "customer-secret.py"
        secret_file.write_text("x = 1\n", encoding="utf-8")
        self.run_trace("snapshot", "--root", root, "--title", "Private customer edit")
        first = self.public(root)
        first_alias = first["latest_files"][0]["path"]
        self.run_trace("event", "--root", root, "--title", "Private milestone", "--detail", "private detail")
        second = self.public(root)
        self.assertEqual(first_alias, second["latest_files"][0]["path"])
        serialized = json.dumps(second)
        for secret in ("customer-secret", "Private customer edit", "Private milestone", "private detail"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("trace_id", second)
        self.assertIn("generation", second)

    def test_strict_mode_hides_custom_kinds_suffixes_and_keeps_plan_replay_keys(self) -> None:
        root = self.initialize(privacy="strict")
        (root / "patient.alice-smith").write_text("private\n", encoding="utf-8")
        self.run_trace("snapshot", "--root", root, "--title", "private edit")
        self.run_trace("event", "--root", root, "--kind", "acme-client", "--title", "custom")
        plans = [
            {"method": "turn/plan/updated", "params": {"plan": [{"step": "Private step", "status": "in_progress"}]}},
            {"method": "turn/plan/updated", "params": {"plan": [{"step": "Private renamed step", "status": "completed"}]}},
        ]
        self.run_trace(
            "ingest", "--root", root, "--source", "app-server",
            input_bytes=b"".join(json.dumps(item).encode() + b"\n" for item in plans),
        )
        public = self.public(root)
        serialized = json.dumps(public)
        for private in ("alice-smith", "acme-client", "Acme-Client", "Private step", "Private renamed"):
            self.assertNotIn(private, serialized)
        self.assertTrue(all("." not in item["path"] for item in public["latest_files"]))
        custom = [event for event in public["events"] if event["kind"] == "activity"]
        self.assertTrue(custom)
        plan_events = [event for event in public["events"] if event["kind"] == "plan"]
        self.assertTrue(plan_events)
        self.assertTrue(all(event.get("data", {}).get("plan_id", "").startswith("step-") for event in plan_events))
        self.assertTrue(all(event.get("data", {}).get("plan_title", "").startswith("Step ") for event in plan_events))

    def test_token_invariants_are_transactional_and_derived(self) -> None:
        root = self.initialize()
        self.run_trace(
            "tokens", "--root", root, "--source", "estimate", "--quality", "estimated",
            "--user-visible", 100, "--effective-user", 40,
            "--candidate-context", 1000, "--retained-context", 250,
        )
        before = self.state(root)["token_usage"]
        self.assertEqual(before["saved_tokens"], 750)
        self.assertEqual(before["field_quality"]["effective_user_tokens"], "derived")
        self.assertEqual(before["field_quality"]["saved_tokens"], "derived")
        self.run_trace(
            "tokens", "--root", root, "--source", "estimate", "--quality", "estimated",
            "--candidate-context", 100, "--retained-context", 20, "--saved", 999,
            expected=1,
        )
        self.assertEqual(self.state(root)["token_usage"], before)

    def test_official_codex_jsonl_shapes_and_usage(self) -> None:
        root = self.initialize()
        messages = [
            {"type": "turn.started", "turn": {"id": "turn-1"}},
            {"type": "item.completed", "item": {"type": "command_execution", "command": "python -m unittest", "exit_code": 0, "status": "completed"}},
            {"type": "item.completed", "item": {"type": "file_change", "status": "completed", "changes": [{"path": "app.py", "kind": "update"}]}},
            {"type": "turn.completed", "turn": {"id": "turn-1", "status": "completed"}, "usage": {"input_tokens": 100, "cached_input_tokens": 20, "output_tokens": 40, "reasoning_output_tokens": 5}},
        ]
        body = b"".join(json.dumps(message).encode() + b"\n" for message in messages)
        self.run_trace("ingest", "--root", root, "--source", "codex-jsonl", input_bytes=body)
        state = self.state(root)
        kinds = [event["kind"] for event in state["events"]]
        self.assertIn("command", kinds)
        self.assertIn("edit", kinds)
        self.assertIn("tokens", kinds)
        self.assertEqual(state["token_usage"]["model_input_tokens"], 100)
        self.assertEqual(state["token_usage"]["field_source"]["model_input_tokens"], "codex-jsonl")

    def test_nested_codex_jsonl_usage_is_not_promoted_to_exact(self) -> None:
        root = self.initialize()
        message = {
            "type": "turn.completed",
            "turn": {
                "id": "turn-untrusted",
                "status": "completed",
                "usage": {"input_tokens": 999, "output_tokens": 888},
            },
        }
        self.run_trace(
            "ingest", "--root", root, "--source", "codex-jsonl",
            input_bytes=json.dumps(message).encode() + b"\n",
        )
        state = self.state(root)
        self.assertNotIn("model_input_tokens", state["token_usage"])
        self.assertFalse(any(event["kind"] == "tokens" for event in state["events"]))

    def test_streamed_plan_snapshot_replaces_renamed_step(self) -> None:
        root = self.initialize()
        messages = [
            {"method": "turn/plan/updated", "params": {"plan": [{"step": "Old wording", "status": "in_progress"}]}},
            {"method": "turn/plan/updated", "params": {"plan": [{"step": "Renamed wording", "status": "completed"}]}},
        ]
        body = b"".join(json.dumps(message).encode() + b"\n" for message in messages)
        self.run_trace("ingest", "--root", root, "--source", "app-server", input_bytes=body)
        plan = self.state(root)["plan"]
        self.assertEqual([(item["title"], item["status"]) for item in plan], [("Renamed wording", "completed")])
        self.run_trace("finish", "--root", root, "--status", "completed", "--summary", "done")

    def test_app_server_token_event_cannot_be_forged_by_source_label(self) -> None:
        root = self.initialize()
        body = json.dumps({"method": "thread/tokenUsage/updated", "params": {"input_tokens": 999}}).encode() + b"\n"
        self.run_trace("ingest", "--root", root, "--source", "codex-jsonl", input_bytes=body)
        self.assertNotIn("model_input_tokens", self.state(root)["token_usage"])

    def test_ingest_omits_raw_approval_and_error_text(self) -> None:
        root = self.initialize()
        marker = "SYNTHETIC-MEDICAL-RECORD-ALICE"
        messages = [
            {"method": "permissionRequest", "reason": marker},
            {"method": "turn/error", "error": {"message": marker}},
        ]
        self.run_trace(
            "ingest", "--root", root, "--source", "app-server",
            input_bytes=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
        )
        self.assertNotIn(marker, json.dumps(self.public(root)))

    def test_malformed_deep_and_oversized_jsonl_is_skipped(self) -> None:
        root = self.initialize()
        malformed = [b"null\n", b"true\n", b"[]\n", b"{\"method\":NaN}\n"]
        value: object = {"type": "item.completed"}
        for _ in range(100):
            value = {"nested": value}
        malformed.append(json.dumps(value).encode() + b"\n")
        malformed.append(b"{" + b"x" * (4 * 1024 * 1024 + 8) + b"}\n")
        valid = json.dumps({"type": "item.completed", "item": {"type": "command_execution", "command": "true", "exit_code": 0}}).encode() + b"\n"
        path = root / "events.jsonl"
        path.write_bytes(b"".join(malformed) + valid)
        result = self.run_trace("ingest", "--root", root, "--source", "codex-jsonl", "--file", path)
        self.assertIn(b"Ingested 1 observable events", result.stdout)

    def test_hook_primitives_fail_open(self) -> None:
        root = self.initialize()
        before = self.state(root)["revision"]
        for raw in (b"null", b"[]", b"true", b"{\"cwd\":[]}"):
            result = self.run_trace("hook", input_bytes=raw)
            self.assertEqual(result.stdout.strip(), b"{}")
        self.assertEqual(self.state(root)["revision"], before)

    def test_malformed_but_valid_private_state_is_normalized(self) -> None:
        root = self.initialize()
        path = root / ".codex-visualizer" / "trace.json"
        malformed = {
            "status": "active", "trace_id": "trace", "started_at": "2026-01-01T00:00:00Z",
            "events": ["bad"], "plan": ["bad"], "latest_files": "bad",
            "baseline": {"x": "bad"}, "observability": "bad", "revision": "bad",
            "_pending_observations": {"x": "bad"},
        }
        path.write_text(json.dumps(malformed), encoding="utf-8")
        result = self.run_trace("event", "--root", root, "--title", "recovered")
        self.assertNotIn(b"Traceback", result.stderr)
        state = self.state(root)
        self.assertEqual(state["events"][-1]["title"], "recovered")
        self.assertEqual(state["plan"], [])

    def test_html_and_markdown_exports_neutralize_markup(self) -> None:
        root = self.initialize(privacy="demo")
        marker = "</ScRiPt><script>globalThis.pwned=1</script><img src=https://example.invalid/pixel> ![pixel](https://example.invalid/track) [link](https://example.invalid/)"
        self.run_trace("event", "--root", root, "--title", marker, "--detail", marker)
        html_path = Path(self.run_trace("export", "--root", root, "--format", "html").stdout.decode().strip())
        html = html_path.read_text(encoding="utf-8")
        self.assertNotIn(marker, html)
        self.assertNotIn("</ScRiPt>", html)
        self.assertIn('"strict_fallback":true', html)
        self.assertIn('"applied_mode":"strict"', html)
        self.assertIn('id="codexTracePayload" type="application/json">', html)
        self.assertNotIn('<script src="events.js"></script>', html)
        self.assertNotIn("window.CODEX_BUILD_TRACE=", html)
        self.assertIn('"standalone":true', html)
        md_path = Path(self.run_trace("export", "--root", root, "--format", "markdown").stdout.decode().strip())
        markdown = md_path.read_text(encoding="utf-8")
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("https://example.invalid", markdown)
        self.assertNotIn("![", markdown)
        self.assertNotIn("](", markdown)

    def test_run_redacts_split_secret_arguments_and_demo_excerpt_boundary(self) -> None:
        root = self.initialize(privacy="demo")
        secret = "sk-proj-ABCDEFGHIJKLMNOPQRST"
        self.run_trace(
            "run", "--root", root, "--kind", "command", "--label", "secret argv", "--",
            sys.executable, "-c", "pass", "--token", secret, "--password", "two words",
        )
        output = "A" * 95 + secret + " " + "B" * (6100 - 96 - len(secret))
        self.run_trace(
            "run", "--root", root, "--kind", "command", "--label", "boundary", "--include-output", "--",
            sys.executable, "-c", f"print({output!r}, end='')",
        )
        serialized = json.dumps(self.public(root))
        for leaked in (secret, "ABCDEFGHIJKLMNOPQRST", "two words"):
            self.assertNotIn(leaked, serialized)
        command = [event for event in self.state(root)["events"] if event["title"] == "secret argv"][0]["data"]["command"]
        self.assertIn("--token [REDACTED]", command)
        self.assertIn("--password [REDACTED]", command)

    def test_run_redacts_curl_user_and_multivalue_authorization_arguments(self) -> None:
        root = self.initialize()
        secrets = ("alice:PlaintextPassword987", "Bearer", "PlaintextOpaqueCredential987")
        self.run_trace(
            "run", "--root", root, "--kind", "command", "--label", "curl auth", "--",
            sys.executable, "-c", "pass", "-u", secrets[0], "--proxy-user", "proxy:OtherPassword987",
            "--authorization", secrets[1], secrets[2], "-uattached:AttachedPassword987", "--cookie", "session=CookieSecret987",
            "--passphrase", "PassphraseSecret987", "/password", "WindowsSecret987",
        )
        command = self.state(root)["events"][-1]["data"]["command"]
        for secret in (secrets[0], "proxy:OtherPassword987", secrets[1], secrets[2], "AttachedPassword987", "CookieSecret987", "PassphraseSecret987", "WindowsSecret987"):
            self.assertNotIn(secret, command)

        module = load_module()
        rendered = module.safe_command_text(["curl", "--authorization", "opaquePASS987", "https://example.invalid"])
        self.assertIn("https://example.invalid", rendered)
        self.assertNotIn("opaquePASS987", rendered)

    @unittest.skipIf(os.name == "nt", "POSIX link semantics")
    def test_managed_links_cannot_clobber_or_disclose(self) -> None:
        root = self.base / "links"
        root.mkdir()
        outside = self.base / "outside"
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_text("unchanged", encoding="utf-8")
        (root / ".codex-visualizer").symlink_to(outside, target_is_directory=True)
        self.run_trace("init", "--root", root, "--title", "unsafe", expected=1)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

        (root / ".codex-visualizer").unlink()
        trace = root / ".codex-visualizer"
        trace.mkdir(mode=0o700)
        (trace / "trace.json").symlink_to(victim)
        self.run_trace("init", "--root", root, "--title", "unsafe", expected=1)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((trace / "archive").exists())

        (trace / "trace.json").unlink()
        (trace / ".trace.lock").unlink()
        os.link(victim, trace / ".trace.lock")
        self.run_trace("init", "--root", root, "--title", "unsafe", expected=1)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipIf(os.name == "nt", "POSIX link semantics")
    def test_atomic_replacement_does_not_follow_viewer_or_export_links(self) -> None:
        root = self.initialize()
        victim = self.base / "victim.txt"
        victim.write_text("unchanged", encoding="utf-8")
        viewer = root / ".codex-visualizer" / "index.html"
        viewer.unlink()
        viewer.symlink_to(victim)
        self.run_trace("event", "--root", root, "--title", "refresh")
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse(viewer.is_symlink())

        viewer.unlink()
        os.link(victim, viewer)
        self.run_trace("event", "--root", root, "--title", "hardlink refresh")
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(viewer.stat().st_nlink, 1)

        output = self.base / "portable.html"
        output.symlink_to(victim)
        self.run_trace("export", "--root", root, "--format", "html", "--output", output)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse(output.is_symlink())

        export_dir = root / ".codex-visualizer" / "export"
        outside_dir = self.base / "outside-export"
        outside_dir.mkdir()
        export_dir.symlink_to(outside_dir, target_is_directory=True)
        self.run_trace("export", "--root", root, "--format", "json", expected=1)
        self.run_trace("export", "--root", root, "--format", "json", "--output", export_dir / "explicit.json", expected=1)
        self.assertEqual(list(outside_dir.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX FIFO semantics")
    def test_managed_fifo_is_rejected_without_blocking(self) -> None:
        root = self.initialize()
        state_path = root / ".codex-visualizer" / "trace.json"
        state_path.unlink()
        os.mkfifo(state_path, 0o600)
        started = time.monotonic()
        result = self.run_trace("status", "--root", root, expected=1, timeout=3)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_export_cannot_overwrite_managed_state_or_rechmod_unrelated_parent(self) -> None:
        root = self.initialize()
        before = (root / ".codex-visualizer" / "trace.json").read_bytes()
        self.run_trace(
            "export", "--root", root, "--format", "json", "--output",
            root / ".codex-visualizer" / "trace.json", expected=1,
        )
        self.assertEqual((root / ".codex-visualizer" / "trace.json").read_bytes(), before)
        external = self.base / "export"
        external.mkdir(mode=0o755)
        self.run_trace("export", "--root", root, "--format", "json", "--output", external / "trace.json")
        if os.name != "nt":
            self.assertEqual(external.stat().st_mode & 0o777, 0o755)

    def test_hooks_install_uninstall_preserves_existing_configuration(self) -> None:
        root = self.initialize()
        codex = root / ".codex"
        codex.mkdir()
        existing = {"description": "existing", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "existing-hook"}]}]}}
        (codex / "hooks.json").write_text(json.dumps(existing), encoding="utf-8")
        self.run_trace("hooks", "--root", root, "--install")
        installed = json.loads((codex / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("existing-hook", json.dumps(installed))
        self.assertIn("trace.py hook", json.dumps(installed))
        self.run_trace("snapshot", "--root", root)
        self.assertFalse(any(item["path"] == ".codex/hooks.json" for item in self.state(root)["latest_files"]))
        self.run_trace("hooks", "--root", root, "--uninstall")
        uninstalled = json.loads((codex / "hooks.json").read_text(encoding="utf-8"))
        serialized = json.dumps(uninstalled)
        self.assertIn("existing-hook", serialized)
        self.assertNotIn("trace.py hook", serialized)
        self.assertFalse(self.state(root)["observability"]["hooks"])
        self.assertTrue(self.state(root)["observability"]["hooks_ever_installed"])

    def test_hooks_use_current_interpreter_and_replace_legacy_owned_hook(self) -> None:
        root = self.initialize()
        codex = root / ".codex"
        codex.mkdir()
        legacy = f"python3 -B {TRACE} hook"
        current = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": legacy}]}]}}
        unrelated = f"echo {TRACE}.not-the-visualizer hook"
        exact_path_unrelated = f"echo {TRACE} hook"
        current["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": unrelated}]})
        current["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": exact_path_unrelated}]})
        (codex / "hooks.json").write_text(json.dumps(current), encoding="utf-8")
        self.run_trace("hooks", "--root", root, "--install")
        installed = json.loads((codex / "hooks.json").read_text(encoding="utf-8"))
        commands = [hook["command"] for group in installed["hooks"]["Stop"] for hook in group["hooks"]]
        self.assertEqual(len(commands), 3)
        self.assertIn(unrelated, commands)
        self.assertIn(exact_path_unrelated, commands)
        generated = next(command for command in commands if command not in {unrelated, exact_path_unrelated})
        self.assertIn(str(Path(sys.executable).resolve()), generated)
        self.run_trace("hooks", "--root", root, "--uninstall")
        uninstalled = json.loads((codex / "hooks.json").read_text(encoding="utf-8"))
        remaining = uninstalled.get("hooks", {}).get("Stop", [])
        self.assertEqual(
            [hook["command"] for group in remaining for hook in group["hooks"]],
            [unrelated, exact_path_unrelated],
        )

    def test_hook_uninstall_syncs_state_when_configuration_was_deleted(self) -> None:
        root = self.initialize()
        self.run_trace("hooks", "--root", root, "--install")
        (root / ".codex" / "hooks.json").unlink()
        self.run_trace("hooks", "--root", root, "--uninstall")
        self.assertFalse(self.state(root)["observability"]["hooks"])

    def test_overlapping_hook_sessions_keep_independent_pending_tools(self) -> None:
        root = self.initialize()

        def hook(event: str, session: str, **extra: object) -> None:
            payload = {"cwd": str(root), "hook_event_name": event, "session_id": session, **extra}
            self.run_trace("hook", input_bytes=json.dumps(payload).encode())

        hook("SessionStart", "session-a", model="model-a")
        hook("SessionStart", "session-b", model="model-b")
        hook("PreToolUse", "session-a", tool_use_id="shared-id", tool_name="Read")
        hook("PreToolUse", "session-b", tool_use_id="shared-id", tool_name="Write")
        hook("PostToolUse", "session-a", tool_use_id="shared-id", tool_name="Read", tool_response={"success": True})
        hook("PostToolUse", "session-b", tool_use_id="shared-id", tool_name="Write", tool_response={"success": True})
        state = self.state(root)
        tools = [event for event in state["events"] if event["kind"] == "tool"]
        self.assertEqual([event["data"]["tool_name"] for event in tools], ["Read", "Write"])
        self.assertEqual(set(state["_hook_sessions"]), {"session-a", "session-b"})
        hook("SessionEnd", "session-a")
        self.assertEqual(set(self.state(root)["_hook_sessions"]), {"session-b"})

    def test_final_snapshot_clears_current_view_after_workspace_rollback(self) -> None:
        root = self.initialize()
        (root / "changed.py").write_text("x = 1\n", encoding="utf-8")
        self.run_trace("snapshot", "--root", root, "--title", "Implemented")
        before = self.state(root)["latest_files"]
        (root / "changed.py").unlink()
        self.run_trace("finish", "--root", root, "--status", "completed", "--summary", "done")
        state = self.state(root)
        self.assertEqual(state["latest_files"], [])
        edits = [event for event in state["events"] if event["kind"] == "edit"]
        self.assertEqual(edits[-1]["data"]["files"], [])
        self.assertEqual(edits[-2]["data"]["files"], before)

    def test_test_evidence_overrides_zero_exit_and_parses_unittest(self) -> None:
        root = self.initialize()
        self.run_trace(
            "run", "--root", root, "--kind", "test", "--label", "contradictory", "--",
            sys.executable, "-c", "print('1 failed, 2 passed')",
        )
        event = self.state(root)["events"][-1]
        self.assertEqual(event["status"], "failure")
        self.assertEqual(event["data"]["tests"]["failed"], 1)
        self.run_trace(
            "run", "--root", root, "--kind", "test", "--label", "unittest", "--",
            sys.executable, "-c", "print('Ran 3 tests in 0.01s\\n\\nOK')",
        )
        tests = self.state(root)["events"][-1]["data"]["tests"]
        self.assertEqual((tests["passed"], tests["total"]), (3, 3))

    def test_timeout_terminates_process_group(self) -> None:
        root = self.initialize()
        marker = root / "orphan-marker"
        child = f"import time,pathlib;time.sleep(.7);pathlib.Path({str(marker)!r}).write_text('alive')"
        parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(30)"
        started = time.monotonic()
        self.run_trace(
            "run", "--root", root, "--kind", "command", "--label", "timeout", "--timeout", 0.15, "--",
            sys.executable, "-c", parent, expected=124, timeout=5,
        )
        self.assertLess(time.monotonic() - started, 3)
        time.sleep(0.9)
        self.assertFalse(marker.exists())

    def test_running_command_cannot_contaminate_replacement_trace(self) -> None:
        root = self.initialize()
        process = subprocess.Popen(
            [sys.executable, "-B", str(TRACE), "run", "--root", str(root), "--kind", "command", "--label", "old-run", "--", sys.executable, "-c", "import time;time.sleep(.4)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(0.1)
        old_id = self.state(root)["trace_id"]
        self.run_trace("init", "--root", root, "--title", "replacement")
        process.communicate(timeout=5)
        state = self.state(root)
        self.assertNotEqual(old_id, state["trace_id"])
        self.assertFalse(any(event["title"] == "old-run" for event in state["events"]))

    def test_concurrent_events_are_not_lost(self) -> None:
        root = self.initialize()
        results: list[int] = []

        def worker(index: int) -> None:
            result = subprocess.run(
                [sys.executable, "-B", str(TRACE), "event", "--root", str(root), "--title", f"event-{index}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            results.append(result.returncode)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, [0] * 24)
        state = self.state(root)
        titles = {event["title"] for event in state["events"]}
        self.assertTrue({f"event-{index}" for index in range(24)} <= titles)
        sequences = [event["seq"] for event in state["events"]]
        self.assertEqual(len(sequences), len(set(sequences)))

    def test_archive_and_event_retention_are_bounded(self) -> None:
        root = self.initialize()
        for index in range(25):
            self.run_trace("init", "--root", root, "--title", f"generation-{index}")
        archives = list((root / ".codex-visualizer" / "archive").glob("trace-*.json"))
        self.assertLessEqual(len(archives), 20)
        module = load_module()
        state = self.state(root)
        module.add_event(state, "test", "important failure", status="failure")
        for index in range(module.MAX_EVENTS + 10):
            module.add_event(state, "note", str(index))
        module.compact_events(state)
        self.assertEqual(len(state["events"]), module.MAX_EVENTS)
        self.assertGreater(state["observability"]["events_dropped"], 0)
        self.assertTrue(any(event.get("title") == "important failure" for event in state["events"]))
        with module.state_lock(root):
            module.save_state(root, state)
        public = self.public(root)
        self.assertTrue(public["observability"]["timeline_truncated"])
        self.assertGreater(public["observability"]["events_dropped"], 0)
        viewer = (SKILL / "assets" / "viewer.html").read_text(encoding="utf-8")
        self.assertIn("retention-warning", viewer)

    def test_state_size_preflight_preserves_readable_previous_state(self) -> None:
        root = self.initialize()
        module = load_module()
        before = self.state(root)
        module.MAX_STATE_BYTES = 12_000
        state = self.state(root)
        state["_oversize_test"] = "X" * 20_000
        with self.assertRaises(SystemExit):
            with module.state_lock(root):
                module.save_state(root, state)
        self.assertEqual(self.state(root), before)

    def test_monorepo_scope_and_large_same_size_change(self) -> None:
        repo = self.base / "repo"
        project = repo / "project"
        sibling = repo / "sibling"
        project.mkdir(parents=True)
        sibling.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        (project / "inside.txt").write_text("inside\n", encoding="utf-8")
        (sibling / "outside.txt").write_text("outside\n", encoding="utf-8")
        large = project / "large.bin"
        large.write_bytes(b"A" * (5 * 1024 * 1024 + 1))
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
        self.run_trace("init", "--root", project, "--title", "subproject")
        (sibling / "outside.txt").write_text("changed outside\n", encoding="utf-8")
        with large.open("r+b") as handle:
            handle.seek(10)
            handle.write(b"B")
        self.run_trace("snapshot", "--root", project)
        paths = [item["path"] for item in self.state(project)["latest_files"]]
        self.assertIn("large.bin", paths)
        self.assertFalse(any("sibling" in path for path in paths))

    def test_trace_artifacts_do_not_dirty_git_repository(self) -> None:
        root = self.base / "clean-repo"
        root.mkdir()
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        (root / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True)
        self.run_trace("init", "--root", root, "--title", "clean")
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], check=True, stdout=subprocess.PIPE).stdout
        self.assertEqual(status, b"")

    @unittest.skipIf(os.name == "nt", "POSIX filenames")
    def test_non_utf8_filename_does_not_crash(self) -> None:
        root = self.base / "non-utf8"
        root.mkdir()
        descriptor = os.open(os.fsencode(root) + b"/bad-\xff.txt", os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(descriptor, b"x\n")
        os.close(descriptor)
        self.run_trace("init", "--root", root, "--title", "non-utf8")
        self.assertTrue((root / ".codex-visualizer" / "trace.json").exists())

    def test_diff_parser_is_hunk_aware(self) -> None:
        module = load_module()
        diff = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n---code\n+++code\n"
        parsed = module.parse_unified_diff(diff)
        self.assertEqual((parsed[0]["added"], parsed[0]["deleted"]), (1, 1))

    def test_finish_rejects_unresolved_plan(self) -> None:
        root = self.initialize()
        self.run_trace("plan", "--root", root, "--id", "pending", "--title", "Pending", "--status", "pending")
        self.run_trace("finish", "--root", root, "--status", "completed", "--summary", "done", expected=1)
        self.assertEqual(self.state(root)["status"], "active")

    def test_invalid_timeout_and_missing_ingest_file_fail_cleanly(self) -> None:
        root = self.initialize()
        for timeout in ("nan", "inf", "0", "-1", "1e20"):
            result = self.run_trace(
                "run", "--root", root, "--kind", "command", "--label", "invalid", "--timeout", timeout,
                "--", sys.executable, "-c", "pass", expected=1,
            )
            self.assertNotIn(b"Traceback", result.stderr)
        result = self.run_trace(
            "ingest", "--root", root, "--source", "codex-jsonl", "--file", root / "missing.jsonl", expected=1,
        )
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertIn(b"Cannot open ingestion file", result.stderr)

    def test_incremental_scan_reuses_unchanged_files_and_full_bypasses_cache(self) -> None:
        root = self.initialize()
        (root / "one.py").write_text("one\n", encoding="utf-8")
        self.run_trace("snapshot", "--root", root)
        first = self.state(root)["observability"]["last_scan"]
        self.assertEqual((first["hashed"], first["reused"]), (1, 0))
        self.run_trace("snapshot", "--root", root)
        second = self.state(root)["observability"]["last_scan"]
        self.assertEqual((second["hashed"], second["reused"]), (0, 1))
        self.run_trace("snapshot", "--root", root, "--full")
        third = self.state(root)["observability"]["last_scan"]
        self.assertEqual((third["hashed"], third["reused"]), (1, 0))

    def test_partial_scan_never_infers_deletion_from_absence(self) -> None:
        root = self.base / "partial-scan"
        root.mkdir()
        for name in ("a.txt", "b.txt", "c.txt"):
            (root / name).write_text(name, encoding="utf-8")
        module = load_module()
        cache = {name: module.fingerprint(root / name) for name in ("a.txt", "b.txt", "c.txt")}
        state = {"_scan_cache": cache, "observability": {}}
        module.MAX_SCAN_FILES = 2
        module.git_file_list = lambda _root: ["a.txt", "b.txt", "c.txt"]
        partial, incomplete = module.scan_workspace(root, state)
        self.assertTrue(incomplete)
        self.assertIn("c.txt", partial)
        self.assertEqual(module.compare_files(cache, partial), [])

        (root / "c.txt").unlink()
        module.git_file_list = lambda _root: ["a.txt", "b.txt"]
        complete, incomplete = module.scan_workspace(root, state)
        self.assertFalse(incomplete)
        self.assertEqual(
            [item["path"] for item in module.compare_files(cache, complete)],
            ["c.txt"],
        )

    def test_first_unstable_fingerprint_is_partial_and_not_a_deletion(self) -> None:
        root = self.base / "unstable-first"
        root.mkdir()
        target = root / "kept.txt"
        target.write_text("kept\n", encoding="utf-8")
        module = load_module()
        baseline = {"kept.txt": module.fingerprint(target)}
        state = {"baseline": baseline, "_scan_cache": {}, "observability": {}}
        module.git_file_list = lambda _root: ["kept.txt"]
        module.fingerprint = lambda _path: None
        current, partial = module.scan_workspace(root, state)
        self.assertTrue(partial)
        self.assertIn("kept.txt", current)
        self.assertEqual(module.compare_files(baseline, current), [])
        self.assertEqual(state["observability"]["last_scan"]["unstable"], 1)

    def test_automatic_snapshot_ticket_is_recoverable(self) -> None:
        module = load_module()
        state = {"snapshot_policy": {"mode": "auto", "debounce_ms": 100}, "_auto_snapshot": {}}
        first = module.schedule_automatic_snapshot(state)
        self.assertIsNotNone(first)
        self.assertIsNone(module.schedule_automatic_snapshot(state))
        # After the spawn grace period, an unclaimed ticket is returned again so
        # a later hook can restart a crashed launch without spawning a storm.
        state["_auto_snapshot"]["ticket_created_at_ms"] -= module.AUTO_SNAPSHOT_SPAWN_GRACE_MS + 1
        self.assertEqual(module.schedule_automatic_snapshot(state), first)
        auto = state["_auto_snapshot"]
        auto["worker_started_at_ms"] = round(time.time() * 1_000)
        auto["lease_until_ms"] = 1
        replacement = module.schedule_automatic_snapshot(state)
        self.assertIsNotNone(replacement)
        self.assertNotEqual(replacement, first)

    def test_isolated_edit_hook_creates_one_automatic_snapshot(self) -> None:
        root = self.initialize()
        session = {"cwd": str(root), "session_id": "s"}
        self.run_trace("hook", input_bytes=json.dumps({**session, "hook_event_name": "SessionStart"}).encode())
        (root / "auto.py").write_text("auto\n", encoding="utf-8")
        self.run_trace("hook", input_bytes=json.dumps({
            **session, "hook_event_name": "PreToolUse", "tool_use_id": "t", "tool_name": "apply_patch",
        }).encode())
        started = time.monotonic()
        self.run_trace("hook", input_bytes=json.dumps({
            **session, "hook_event_name": "PostToolUse", "tool_use_id": "t", "tool_name": "apply_patch",
            "tool_response": {"success": True},
        }).encode())
        self.assertLess(time.monotonic() - started, 1.1)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            state = self.state(root)
            if (state.get("observability") or {}).get("automatic_snapshots") == 1:
                break
            time.sleep(.15)
        state = self.state(root)
        self.assertEqual(state["observability"]["automatic_snapshots"], 1)
        self.assertEqual(state["latest_files"][0]["path"], "auto.py")
        self.assertNotIn("ticket", state.get("_auto_snapshot", {}))

    def test_token_import_adapters_trends_and_duplicate_turns(self) -> None:
        root = self.initialize()
        payload = root / "usage.json"
        payload.write_text(json.dumps({"usage": {
            "input_tokens": 100, "output_tokens": 20,
            "input_tokens_details": {"cached_tokens": 40},
            "output_tokens_details": {"reasoning_tokens": 5},
        }}), encoding="utf-8")
        self.run_trace("tokens", "--root", root, "--input", payload, "--adapter", "api")
        public = self.public(root)
        self.assertEqual(public["token_usage"]["model_input_tokens"], 100)
        self.assertEqual(public["token_usage"]["cached_input_tokens"], 40)
        self.assertEqual(public["token_usage"]["trends"]["actual"][0]["values"]["model_output_tokens"], 20)
        message = {"type": "turn.completed", "turn": {"id": "same", "status": "completed"}, "usage": {"input_tokens": 7, "output_tokens": 2}}
        raw = (json.dumps(message) + "\n" + json.dumps(message) + "\n").encode()
        self.run_trace("ingest", "--root", root, "--source", "codex-jsonl", input_bytes=raw)
        state = self.state(root)
        token_events = [event for event in state["events"] if event.get("kind") == "tokens"]
        self.assertEqual(len(token_events), 2)
        self.assertEqual(state["token_usage"]["model_input_tokens"], 7)
        self.assertNotIn("cached_input_tokens", state["token_usage"])

    def test_token_auto_adapter_rejects_ambiguous_and_nested_shapes(self) -> None:
        root = self.initialize()
        ambiguous = root / "ambiguous.json"
        ambiguous.write_text(json.dumps({
            "type": "response.completed",
            "usage": {"input_tokens": 10, "output_tokens": 2},
            "attributes": {
                "gen_ai.usage.input_tokens": 10,
                "gen_ai.usage.output_tokens": 2,
            },
        }), encoding="utf-8")
        result = self.run_trace(
            "tokens", "--root", root, "--input", ambiguous, "--adapter", "auto", expected=1,
        )
        self.assertIn(b"ambiguous", result.stderr)
        self.assertFalse(any(event["kind"] == "tokens" for event in self.state(root)["events"]))

        nested = root / "nested.json"
        nested.write_text(json.dumps({
            "payload": {"usage": {"input_tokens": 999, "output_tokens": 888}},
        }), encoding="utf-8")
        result = self.run_trace(
            "tokens", "--root", root, "--input", nested, "--adapter", "auto", expected=1,
        )
        self.assertIn(b"did not recognize", result.stderr)

        otel = root / "otel.json"
        otel.write_text(json.dumps({
            "name": "response.completed", "span_id": "span-1", "trace_id": "trace-1",
            "attributes": {
                "gen_ai.usage.input_tokens": 21,
                "gen_ai.usage.cached_input_tokens": 8,
                "gen_ai.usage.output_tokens": 5,
                "gen_ai.usage.reasoning_tokens": 2,
            },
        }), encoding="utf-8")
        self.run_trace("tokens", "--root", root, "--input", otel, "--adapter", "auto")
        usage = self.state(root)["token_usage"]
        self.assertEqual(usage["field_source"]["model_input_tokens"], "otel")
        self.assertEqual(usage["semantics"], "delta")

    def test_token_cli_sample_id_dedup_and_adapter_state_bound(self) -> None:
        root = self.initialize()
        command = (
            "tokens", "--root", root, "--source", "manual", "--quality", "estimated",
            "--semantics", "delta", "--sample-id", "response-1", "--scope", "session-a",
        )
        self.run_trace(*command, "--model-input", 10, "--model-output", 2)
        revision = self.state(root)["revision"]
        self.run_trace(*command, "--model-input", 999, "--model-output", 99)
        state = self.state(root)
        self.assertEqual(state["revision"], revision)
        self.assertEqual(state["token_usage"]["model_input_tokens"], 10)
        self.assertEqual(sum(event["kind"] == "tokens" for event in state["events"]), 1)
        self.assertNotIn("response-1", json.dumps(state))

        module = load_module()
        for index in range(module.MAX_TOKEN_SAMPLE_IDS + 5):
            module.record_token_sample(
                state, {"model_input_tokens": index + 1}, "manual", "estimated", "sample", "test",
                semantics="delta", sample_id=f"bounded-{index}", scope="session-a",
            )
        self.assertEqual(len(state["_token_adapter_state"]["seen_ids"]), module.MAX_TOKEN_SAMPLE_IDS)

    def test_cumulative_token_increase_repeat_and_reset(self) -> None:
        root = self.initialize()

        def cumulative(model_input: int, cached: int) -> None:
            self.run_trace(
                "tokens", "--root", root, "--source", "app-server", "--quality", "actual",
                "--scope", "thread-a", "--model-input", model_input, "--cached-input", cached,
            )

        cumulative(100, 40)
        cumulative(100, 40)
        cumulative(130, 50)
        cumulative(20, 5)
        state = self.state(root)
        token_events = [event for event in state["events"] if event["kind"] == "tokens"]
        self.assertEqual(len(token_events), 3)
        entries = state["token_usage"]["entries"]
        self.assertEqual(entries[-2]["deltas"], {"model_input_tokens": 30, "cached_input_tokens": 10})
        self.assertTrue(entries[-1]["reset"])
        self.assertNotIn("deltas", entries[-1])
        self.assertEqual(state["token_usage"]["model_input_tokens"], 20)
        self.assertEqual(state["token_usage"]["cached_input_tokens"], 5)
        all_deltas = [value for item in state["token_history"] for value in item.get("deltas", {}).values()]
        self.assertTrue(all(value >= 0 for value in all_deltas))
        self.assertEqual(len(self.public(root)["token_usage"]["trends"]["actual"]), 1)

    def test_failed_ingest_message_is_transactional(self) -> None:
        root = self.initialize()
        started = {"type": "turn.started", "turn": {"id": "atomic-turn"}}
        self.run_trace(
            "ingest", "--root", root, "--source", "codex-jsonl",
            input_bytes=json.dumps(started).encode() + b"\n",
        )
        before = self.state(root)
        invalid = {
            "type": "turn.completed", "turn": {"id": "atomic-turn", "status": "completed"},
            "usage": {"input_tokens": 5, "cached_input_tokens": 9, "output_tokens": 1},
        }
        result = self.run_trace(
            "ingest", "--root", root, "--source", "codex-jsonl",
            input_bytes=json.dumps(invalid).encode() + b"\n",
        )
        self.assertIn(b"Ingested 0 observable events", result.stdout)
        self.assertEqual(self.state(root), before)

    def test_journal_recovers_corrupt_state_and_repairs_public_projection(self) -> None:
        root = self.initialize()
        self.run_trace("event", "--root", root, "--title", "durable")
        state_path = root / ".codex-visualizer" / "trace.json"
        state_path.write_text("{broken", encoding="utf-8")
        self.run_trace("event", "--root", root, "--title", "recovered")
        titles = [event["title"] for event in self.state(root)["events"]]
        self.assertIn("durable", titles)
        self.assertIn("recovered", titles)
        public_path = root / ".codex-visualizer" / "events.js"
        public_path.write_text("tampered", encoding="utf-8")
        self.run_trace("verify", "--root", root, expected=1)
        repaired = self.run_trace("verify", "--root", root, "--repair-public")
        report = json.loads(repaired.stdout)
        self.assertTrue(report["valid"])
        self.assertTrue(report["repaired_public"])

    def test_journal_rejects_schema_downgrade_and_restores_missing_cursor(self) -> None:
        root = self.initialize()
        self.run_trace("event", "--root", root, "--title", "durable")
        state_path = root / ".codex-visualizer" / "trace.json"
        journal_path = root / ".codex-visualizer" / "journal.jsonl"

        state = self.state(root)
        state["title"] = "TAMPERED-BY-SCHEMA-DOWNGRADE"
        state["schema_version"] = 0
        state.pop("integrity", None)
        state_path.write_text(json.dumps(state), encoding="utf-8")
        self.run_trace("event", "--root", root, "--title", "after downgrade")
        repaired = self.state(root)
        self.assertNotEqual(repaired["title"], "TAMPERED-BY-SCHEMA-DOWNGRADE")

        lines_before = journal_path.read_text(encoding="utf-8").splitlines()
        repaired.pop("_journal_hash", None)
        state_path.write_text(json.dumps(repaired), encoding="utf-8")
        self.run_trace("event", "--root", root, "--title", "cursor restored")
        lines_after = journal_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines_after), len(lines_before) + 1)
        self.assertEqual(json.loads(lines_after[-1])["prev"], json.loads(lines_before[-1])["hash"])
        self.run_trace("verify", "--root", root)

    def test_journal_torn_framing_is_sealed_before_next_append(self) -> None:
        root = self.initialize()
        self.run_trace("event", "--root", root, "--title", "before torn frame")
        directory = root / ".codex-visualizer"
        journal_path = directory / "journal.jsonl"
        raw = journal_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        journal_path.write_bytes(raw[:-1])
        self.run_trace("event", "--root", root, "--title", "after torn frame")
        self.assertTrue(journal_path.read_bytes().endswith(b"\n"))
        self.run_trace("verify", "--root", root)
        (directory / "trace.json").write_text("{broken", encoding="utf-8")
        self.run_trace("event", "--root", root, "--title", "after second recovery")
        titles = [event["title"] for event in self.state(root)["events"]]
        self.assertIn("after torn frame", titles)
        self.assertIn("after second recovery", titles)

    def test_journal_complete_midstream_corruption_fails_closed(self) -> None:
        root = self.initialize()
        self.run_trace("event", "--root", root, "--title", "one")
        self.run_trace("event", "--root", root, "--title", "two")
        directory = root / ".codex-visualizer"
        journal_path = directory / "journal.jsonl"
        lines = journal_path.read_text(encoding="utf-8").splitlines()
        middle = json.loads(lines[1])
        middle["hash"] = "0" * 64
        lines[1] = json.dumps(middle, separators=(",", ":"))
        journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (directory / "trace.json").write_text("{broken", encoding="utf-8")
        result = self.run_trace("status", "--root", root, expected=1)
        self.assertIn(b"integrity", result.stderr.lower())

    def test_export_privacy_gate_and_history_summaries(self) -> None:
        root = self.initialize(privacy="standard")
        benign = Path(self.run_trace("export", "--root", root, "--format", "json").stdout.decode().strip())
        self.assertEqual(json.loads(benign.read_text())["export_guard"]["applied_mode"], "standard")
        self.run_trace("event", "--root", root, "--title", "<script>alert(1)</script>")
        guarded = Path(self.run_trace("export", "--root", root, "--format", "json").stdout.decode().strip())
        guarded_data = json.loads(guarded.read_text())
        self.assertEqual(guarded_data["export_guard"]["applied_mode"], "strict")
        self.assertTrue(guarded_data["export_guard"]["strict_fallback"])
        self.run_trace("init", "--root", root, "--title", "next", "--lang", "en", "--privacy", "strict")
        history_export = Path(self.run_trace("export", "--root", root, "--format", "json", "--include-history").stdout.decode().strip())
        history = json.loads(history_export.read_text())["history"]["runs"]
        self.assertEqual(len(history), 1)
        self.assertNotIn("title", history[0])

    def test_public_integrity_and_actor_are_privacy_safe(self) -> None:
        root = self.initialize(privacy="strict")
        module = load_module()
        with module.state_lock(root):
            state = module.load_state(root)
            actor = module.actor_for(state, "private-agent-id", "reviewer")
            module.add_event(state, "agent", "private", actor=actor)
            module.save_state(root, state)
        public = self.public(root)
        event = public["events"][-1]
        self.assertRegex(event["actor"]["lane"], r"^agent-\d+$")
        self.assertNotIn("private-agent-id", json.dumps(public))
        self.assertNotIn("state_checksum", public["integrity"])
        self.assertNotIn("head", public["integrity"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
