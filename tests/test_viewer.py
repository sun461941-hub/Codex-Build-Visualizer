from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SKILL = Path(__file__).resolve().parents[1]
VIEWER = SKILL / "assets" / "viewer.html"


def resolve_jsdom() -> Path | None:
    explicit = os.environ.get("CBV_JSDOM_MODULE")
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.exists() else None
    for root in os.environ.get("NODE_PATH", "").split(os.pathsep):
        if root and (Path(root) / "jsdom").exists():
            return Path(root) / "jsdom"
    probe = subprocess.run(
        ["node", "-e", "try{process.stdout.write(require.resolve('jsdom/package.json'))}catch(e){process.exit(1)}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return Path(probe.stdout).parent if probe.returncode == 0 and probe.stdout else None


JSDOM = resolve_jsdom()
if JSDOM is None and os.environ.get("CBV_REQUIRE_JSDOM") == "1":
    raise RuntimeError("CBV_REQUIRE_JSDOM=1 but jsdom is unavailable")


class ViewerTests(unittest.TestCase):
    def test_inline_javascript_is_valid_and_polling_has_legacy_fallback(self) -> None:
        script = r"""
const fs = require('fs');
const html = fs.readFileSync(process.argv[1], 'utf8');
const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
  .filter(match => !/\bsrc\s*=/.test(match[1]) && !/\btype\s*=/.test(match[1]))
  .map(match => match[2]).filter(Boolean);
for (const source of scripts) new Function(source);
"""
        result = subprocess.run(
            ["node", "-e", script, str(VIEWER)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        html = VIEWER.read_text(encoding="utf-8")
        self.assertIn("meta.js?v=", html)
        self.assertIn("metaFallbackPolls < 3", html)
        self.assertIn("history.js?v=", html)
        self.assertIn("document.hidden", html)
        self.assertIn("window.__codexTraceMeta =", html)
        self.assertIn("receive(window.CODEX_BUILD_TRACE)", html)
        self.assertIn("prefers-reduced-motion", html)
        self.assertEqual(html.count('<script src="events.js"></script>'), 1)
        self.assertEqual(html.count('id="codexTracePayload" type="application/json"'), 1)

    def test_csp_hash_matches_the_only_executable_inline_program(self) -> None:
        html = VIEWER.read_text(encoding="utf-8")
        programs = re.findall(r"<script>([\s\S]*?)</script>", html)
        self.assertEqual(len(programs), 1)
        digest = base64.b64encode(hashlib.sha256(programs[0].encode("utf-8")).digest()).decode("ascii")
        policy = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        self.assertIsNotNone(policy)
        script_source = next(part for part in policy.group(1).split(";") if part.strip().startswith("script-src"))
        self.assertIn(f"'sha256-{digest}'", script_source)
        self.assertNotIn("'unsafe-inline'", script_source)
        self.assertNotIn("REPLACE_WITH_STATIC_PROGRAM_HASH", html)

    @unittest.skipUnless(JSDOM is not None, "jsdom is unavailable; set CBV_JSDOM_MODULE or NODE_PATH")
    def test_5000_event_window_search_trends_lanes_history_and_generation_reset(self) -> None:
        node_test = r"""
const fs = require('fs');
const {JSDOM, VirtualConsole, ResourceLoader} = require(process.argv[3]);
const viewer = process.argv[2];
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

class CountingLoader extends ResourceLoader {
  constructor() { super(); this.requests = []; }
  fetch(url, options) { this.requests.push(url); return super.fetch(url, options); }
}

function baseTrace(events, generation='generation-a', revision=1) {
  return {
    schema_version: 5, generation, generation_order: generation === 'generation-a' ? 1 : 2,
    revision, title: 'Viewer test', project_name: 'project', lang: 'en', privacy_mode: 'standard',
    status: 'active', events, plan: [], latest_files: [],
    token_usage: {
      quality: 'mixed', model_input_tokens: 200, effective_user_tokens: 80, saved_tokens: 120,
      field_quality: {model_input_tokens:'estimated',effective_user_tokens:'derived',saved_tokens:'derived'}
    },
    aggregates: {complete:false},
    observability: {events_dropped: 0}
  };
}

function standaloneHtml(source, trace, history) {
  const payload = JSON.stringify({standalone:true,trace,history}).replaceAll('&','\\u0026').replaceAll('<','\\u003c').replaceAll('>','\\u003e');
  return source
    .replace('<script id="codexTracePayload" type="application/json">{}</script>', `<script id="codexTracePayload" type="application/json">${payload}<\/script>`)
    .replace('<script src="events.js"></script>', '');
}

function fixtureEvents(count) {
  const events = [];
  for (let index=1; index<=count; index++) events.push({
    seq:index, at:new Date(1700000000000 + index*1000).toISOString(),
    kind:index % 9 === 0 ? 'test' : 'note',
    title:index === 321 ? 'Literal [x].* match' : `Event ${index}`,
    detail:index === 321 ? '<img src=x onerror=globalThis.pwned=1>' : 'safe detail',
    status:index % 11 === 0 ? 'failure' : 'success', duration_ms:2,
    data:index % 9 === 0 ? {tests:{passed:1}} : {}
  });
  events[10] = {seq:11,at:new Date().toISOString(),kind:'tokens',title:'Tokens 1',status:'success',data:{token_usage:{model_input_tokens:100,effective_user_tokens:40,saved_tokens:60,field_quality:{model_input_tokens:'actual',effective_user_tokens:'derived',saved_tokens:'derived'},field_source:{model_input_tokens:'app-server'}}}};
  events[20] = {seq:21,at:new Date().toISOString(),kind:'tokens',title:'Tokens 2',status:'success',data:{token_usage:{model_input_tokens:200,effective_user_tokens:80,saved_tokens:120,field_quality:{model_input_tokens:'estimated',effective_user_tokens:'derived',saved_tokens:'derived'},field_source:{model_input_tokens:'estimate'}}}};
  events[30] = {seq:31,at:new Date().toISOString(),kind:'agent',title:'Subagent started',status:'running',data:{agent_id:'RAW-AGENT-IDENTIFIER'}};
  events[40] = {seq:41,at:new Date().toISOString(),kind:'agent',title:'Subagent completed',status:'success',data:{agent_id:'RAW-AGENT-IDENTIFIER'},duration_ms:10};
  return events;
}

(async () => {
  const events = fixtureEvents(5000);
  const attack = '<img id="xss-probe" src=x onerror="globalThis.pwned=1">';
  events[4999] = {seq:5000,at:new Date().toISOString(),kind:'test',title:'Malicious counters',status:attack,duration_ms:attack,data:{tests:{passed:attack,failed:attack,skipped:attack,coverage_percent:attack},tool_name:'HIDDEN-SEARCH-SECRET'}};
  const trace = baseTrace(events);
  trace.plan = [{id:'malicious',title:'Safe plan title',status:attack}];
  trace.latest_files = [{path:'safe.txt',status:'modified',added:attack,deleted:attack}];
  const history = {runs:[{generation:'previous-generation',finished_at:'2025-01-01T00:00:00Z',status:'completed',complete:true,metrics:{total_events:4000,checks:{total:22,passed:20,failed:2},files_changed:4,added:30,deleted:5,diff_quality:'metadata',model_input_tokens:150,model_input_quality:'estimated',agents:1,observed_duration_ms:2000}}]};
  let html = standaloneHtml(fs.readFileSync(viewer,'utf8'),trace,history);
  const errors = [], console = new VirtualConsole(), loader = new CountingLoader();
  console.on('jsdomError', error => errors.push(String(error)));
  const dom = new JSDOM(html,{runScripts:'dangerously',resources:loader,pretendToBeVisual:true,virtualConsole:console});
  const document = dom.window.document;

  assert(!document.querySelector('#xss-probe'), 'untrusted counts and status values must not create elements');
  assert(dom.window.pwned === undefined, 'untrusted counts and status values must not execute');
  assert(document.querySelector('.plan-state').textContent === 'Pending', 'invalid plan status must be normalized');
  assert(document.querySelector('#scrubber').getAttribute('aria-label') === 'Replay position', 'scrubber must have an accessible name');
  assert(document.querySelectorAll('.event').length === 100, 'initial timeline must be bounded to 100 event nodes');
  assert(document.querySelector('.event').getAttribute('aria-setsize') === '5000', 'accessible set size must describe all events');
  assert(!document.querySelector('#olderPage').disabled, 'older-page control must be enabled');
  document.querySelector('#olderPage').click();
  assert(document.querySelectorAll('.event').length === 100, 'second page must remain bounded');
  assert(document.querySelector('.page-label').textContent.includes('2 / 50'), 'pagination must advance');

  const search = document.querySelector('#eventSearch');
  search.value = '[x].*';
  search.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  await delay(160);
  assert(document.querySelectorAll('.event').length === 1, 'search must treat regex characters literally');
  assert(document.querySelector('.event-title').textContent.includes('Literal [x].* match'), 'literal match must be shown');
  assert(dom.window.pwned === undefined, 'searchable markup must remain inert');
  assert(document.querySelector('.page-label').textContent.includes('1 / 1'), 'filter must reset pagination');

  search.value = 'HIDDEN-SEARCH-SECRET';
  search.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  await delay(160);
  assert(document.querySelectorAll('.event').length === 0, 'search must not index fields that are not rendered');

  search.value = '';
  search.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  await delay(160);
  const kind = document.querySelector('#kindFilter');
  kind.value = 'test'; kind.dispatchEvent(new dom.window.Event('change',{bubbles:true}));
  const status = document.querySelector('#statusFilter');
  status.value = 'failure'; status.dispatchEvent(new dom.window.Event('change',{bubbles:true}));
  assert([...document.querySelectorAll('.event')].every(node => node.classList.contains('failure')), 'kind and status filters must combine');

  assert(document.querySelector('.trend-chart'), 'Token trend chart must render');
  assert(document.querySelector('.trend-wrap .data-table'), 'Token trend must have an accessible table');
  assert(!/NaN|Infinity/.test(document.querySelector('.trend-chart').outerHTML), 'trend geometry must stay finite');
  assert(document.querySelectorAll('.trend-dot,.trend-line').length >= 3, 'quality/source changes must create bounded trend segments');
  assert(document.querySelectorAll('.lane-row').length >= 2, 'Main and Agent lanes must render');
  assert(!document.querySelector('#app').innerHTML.includes('RAW-AGENT-IDENTIFIER'), 'raw Agent IDs must not be displayed');
  assert(document.querySelector('#historyRun'), 'history comparison selector must render');
  assert(document.querySelector('.history-body .data-table'), 'history comparison table must render');
  const compareRows = [...document.querySelectorAll('.history-body tbody tr')];
  const eventsRow = compareRows.find(row => row.querySelector('th').textContent === 'Events');
  const passedRow = compareRows.find(row => row.querySelector('th').textContent === 'passed');
  assert(eventsRow.children[2].textContent === '4,000', 'history total_events must map to the previous event count');
  assert(passedRow.children[2].textContent === '20', 'history checks.passed must map to the previous check count');
  assert(eventsRow.children[3].textContent === 'Not comparable', 'an active run must not produce a comparison delta');
  assert(document.querySelector('.history-body').textContent.includes('Partial run'), 'an incomplete comparison must be visibly marked');
  assert(loader.requests.length === 0, 'standalone viewer must not request events, meta, or history files');

  kind.value = 'note'; kind.dispatchEvent(new dom.window.Event('change',{bubbles:true}));
  const replacement = baseTrace(fixtureEvents(257),'generation-b',1);
  dom.window.__codexTraceReceive(replacement);
  assert(document.querySelector('#eventSearch').value === '', 'generation change must clear search');
  assert(document.querySelector('#kindFilter').value === 'all', 'generation change must clear filters');
  assert(document.querySelectorAll('.event').length === 100, 'new generation first page must be bounded');
  document.querySelector('#olderPage').click(); document.querySelector('#olderPage').click();
  assert(document.querySelectorAll('.event').length === 57, '257 events must paginate as 100/100/57');

  const sameSearch = document.querySelector('#eventSearch');
  sameSearch.value = 'Event 2'; sameSearch.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  await delay(160);
  document.querySelector('.timeline').scrollTop = 123;
  dom.window.__codexTraceReceive({...replacement,revision:2,events:[...replacement.events,{seq:258,at:new Date().toISOString(),kind:'note',title:'Event 258',status:'success'}]});
  assert(document.querySelector('#eventSearch').value === 'Event 2', 'same-generation update must preserve search');
  assert(document.querySelector('.timeline').scrollTop === 123, 'same-generation update must preserve timeline scroll');

  const legacy = baseTrace(fixtureEvents(50).slice(0,4));
  delete legacy.generation; delete legacy.generation_order; delete legacy.revision;
  dom.window.__codexTraceReceive(legacy);
  const legacySearch = document.querySelector('#eventSearch');
  legacySearch.value = 'Event'; legacySearch.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  await delay(160);
  dom.window.__codexTraceReceive({...legacy,events:[...legacy.events,{seq:5,at:new Date().toISOString(),kind:'note',title:'Event 5',status:'success'}]});
  assert(document.querySelector('#eventSearch').value === 'Event', 'legacy updates without generation/revision must preserve UI state');
  assert(document.querySelector('#resultStatus').textContent.includes('5 matches'), 'legacy updates without callbacks or revisions must be accepted');

  const highCardinality = baseTrace(fixtureEvents(5000).map((event,index) => ({...event,actor:{lane:`safe-agent-${index}`}})),'high-cardinality',1);
  dom.window.__codexTraceReceive(highCardinality);
  assert(document.querySelectorAll('#laneFilter option').length <= 27, 'high-cardinality Agent data must not create unbounded filter options');
  assert(document.querySelectorAll('*').length < 2500, 'high-cardinality Agent data must keep the total DOM bounded');

  const seqEvents = start => Array.from({length:5000},(_,index)=>({seq:start+index,at:'2026-01-01T00:00:00Z',kind:'note',title:`Seq ${start+index}`,status:'success',data:{}}));
  const retention = baseTrace(seqEvents(1),'retention',1);
  dom.window.__codexTraceReceive(retention);
  let scrubber = document.querySelector('#scrubber');
  scrubber.value = '150'; scrubber.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  dom.window.__codexTraceReceive({...retention,revision:2,events:seqEvents(101)});
  assert(document.querySelector('.frame').textContent.trim() === '50 / 5,000', 'retained replay seq must follow its new array position');
  dom.window.__codexTraceReceive({...retention,revision:3,events:seqEvents(201)});
  assert(document.querySelector('.frame').textContent.trim() === '0 / 5,000', 'dropped replay seq must clamp to the seq boundary, not an old index');

  const strictLegacy = baseTrace(Array.from({length:100},(_,index)=>({seq:index+1,at:'2026-01-01T00:00:00Z',kind:'note',title:`Strict ${index}`,status:'success',data:{agent_id:`RAW-${index}`}})),'strict-legacy',1);
  strictLegacy.privacy_mode = 'strict';
  dom.window.__codexTraceReceive(strictLegacy);
  assert(document.querySelectorAll('#laneFilter option').length === 2, 'strict legacy raw IDs must not create inferred Agent lanes');
  assert(!document.querySelector('#app').innerHTML.includes('RAW-'), 'strict legacy raw IDs must stay out of the DOM');
  assert(errors.length === 0, `unexpected DOM errors: ${errors.join(' | ')}`);
  dom.window.close();
})().catch(error => { console.error(error.stack); process.exit(1); });
"""
        with tempfile.TemporaryDirectory(prefix="viewer-test.") as temporary:
            path = Path(temporary) / "viewer_test.js"
            path.write_text(node_test, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path), str(VIEWER), str(JSDOM)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
