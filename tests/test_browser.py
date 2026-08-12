from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SKILL = Path(__file__).resolve().parents[1]
VIEWER = SKILL / "assets" / "viewer.html"


def inline_json(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


class BrowserTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_real_chromium_standalone_mobile_csp_focus_and_dom_bound(self) -> None:
        probe = subprocess.run(
            ["node", "-e", "process.stdout.write(require('playwright').chromium.executablePath())"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        browser_executable = Path(probe.stdout)
        if probe.returncode or not browser_executable.is_file():
            if os.environ.get("CBV_REQUIRE_BROWSER") == "1":
                self.fail("CBV_REQUIRE_BROWSER=1 but Playwright Chromium is unavailable")
            self.skipTest("Playwright Chromium is unavailable")

        events = [
            {
                "seq": index,
                "at": "2026-01-01T00:00:00Z",
                "kind": "tokens" if index in {10, 20} else "note",
                "title": "Literal [x].* match" if index == 321 else f"Event {index}",
                "detail": "<img src=x onerror=globalThis.pwned=1>" if index == 321 else "safe",
                "status": "success",
                "data": {
                    "token_usage": {
                        "model_input_tokens": index * 10,
                        "field_quality": {"model_input_tokens": "actual"},
                        "field_source": {"model_input_tokens": "api"},
                    }
                } if index in {10, 20} else {},
            }
            for index in range(1, 5_001)
        ]
        attack = '<img id="xss-probe" src=x onerror="globalThis.pwned=1">'
        events[-1]["status"] = attack
        events[-1]["duration_ms"] = attack
        events[-1]["data"] = {
            "tests": {
                "passed": attack,
                "failed": attack,
                "skipped": attack,
                "coverage_percent": attack,
            }
        }
        trace = {
            "schema_version": 6,
            "generation": "browser-generation",
            "generation_order": 1,
            "revision": 1,
            "title": "Browser test",
            "project_name": "project",
            "lang": "en",
            "privacy_mode": "standard",
            "status": "active",
            "events": events,
            "plan": [{"id": "malicious", "title": "Safe title", "status": attack}],
            "latest_files": [
                {"path": "safe.txt", "status": "modified", "added": attack, "deleted": attack}
            ],
            "token_usage": {"quality": "actual", "model_input_tokens": 200},
            "observability": {},
        }
        payload = inline_json({"standalone": True, "trace": trace})
        source = (
            VIEWER.read_text(encoding="utf-8")
            .replace(
                '<script id="codexTracePayload" type="application/json">{}</script>',
                f'<script id="codexTracePayload" type="application/json">{payload}</script>',
            )
            .replace('<script src="events.js"></script>', "")
        )
        node_test = r"""
const {chromium} = require('playwright');
const path = require('path');
(async () => {
  // With `node script.js html chromium`, Node keeps the script at argv[1].
  const browser = await chromium.launch({headless:true, executablePath:process.argv[3]});
  const context = await browser.newContext({viewport:{width:320,height:720}, reducedMotion:'reduce'});
  const page = await context.newPage();
  const failures = [], requests = [];
  page.on('pageerror', error => failures.push(String(error)));
  page.on('request', request => requests.push(request.url()));
  await page.goto('file://' + path.resolve(process.argv[2]), {waitUntil:'load'});
  await page.locator('#eventSearch').waitFor();
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  assert(await page.locator('.event').count() === 100, 'timeline DOM must be bounded');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'mobile page must not overflow horizontally');
  assert(await page.evaluate(() => globalThis.pwned === undefined), 'event markup must remain inert');
  assert(await page.locator('#xss-probe').count() === 0, 'untrusted counts and statuses must not create elements');
  const search = page.getByRole('searchbox', {name:'Search'});
  await search.fill('[x].*');
  await page.waitForTimeout(180);
  assert(await page.locator('.event').count() === 1, 'search must be literal');
  assert((await page.locator('.event-title').textContent()).includes('[x].*'), 'literal result must render');
  await page.evaluate(() => window.__codexTraceReceive({...window.CODEX_BUILD_TRACE, revision:2}));
  assert(await search.inputValue() === '[x].*', 'same-generation refresh must preserve search focus/value');
  assert(await search.evaluate(node => node === document.activeElement), 'same-generation refresh must restore focus');
  const trend = await page.locator('.trend-chart').evaluate(node => node.outerHTML);
  assert(!/NaN|Infinity/.test(trend), 'Token chart geometry must be finite');
  assert(failures.length === 0, `browser errors: ${failures.join(' | ')}`);
  assert(requests.length === 1 && requests[0].startsWith('file:'), 'standalone must make no subresource request');
  await browser.close();
})().catch(error => { console.error(error.stack); process.exit(1); });
"""
        with tempfile.TemporaryDirectory(prefix="visualizer-browser-test.") as temporary:
            directory = Path(temporary)
            html = directory / "standalone.html"
            script = directory / "browser_test.js"
            html.write_text(source, encoding="utf-8")
            script.write_text(node_test, encoding="utf-8")
            result = subprocess.run(
                ["node", str(script), str(html), str(browser_executable)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=45,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
