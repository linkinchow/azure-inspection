"""Fixes from the 0.10.x test rounds (synthetic data, no network)."""
from __future__ import annotations

import sys
import unittest
import urllib.error
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib  # noqa: E402
import os  # noqa: E402

from azinspect.core import http  # noqa: E402

ops = importlib.import_module('azinspect.waf.operations.collect')


class ActivityLogTests(unittest.TestCase):
    def test_start_within_retention(self):
        # 90 days back from the window end fell just outside the 90 days the activity log keeps by the time the
        # request ran: every subscription answered 400
        end = datetime(2026, 11, 1)
        since = ops.activity_since(end, now=end + timedelta(minutes=40))
        self.assertGreater(since, end + timedelta(minutes=40) - timedelta(days=90))
        self.assertLessEqual(since, end - timedelta(days=89))
        later = ops.activity_since(end, now=end + timedelta(days=5))      # collected days after the window
        self.assertGreater(later, end + timedelta(days=5) - timedelta(days=90))


class ScopeTests(unittest.TestCase):
    def test_04_names_its_tenant_wide_check(self):
        # 04's governance check (O8) reads the management groups of the whole tenant; only 03's was named
        import tempfile
        from azinspect import selection
        from azinspect.core import io
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}]})
            cfg = SimpleNamespace(include=['pay-prod'], exclude=[])
            selection.save(ws, ['04'], ['卓越运营'])
            self.assertIn('管理组（治理检查）', selection.subscription_scope(ws, cfg, '04'))
            selection.save(ws, ['03', '04'])
            self.assertIn('管理组（Landing Zone 对照和治理检查）', selection.subscription_scope(ws, cfg))
            selection.save(ws, ['04'], ['性能效率'])
            self.assertNotIn('管理组', selection.subscription_scope(ws, cfg, '04'))

    def test_management_groups_do_not_name_subscriptions_out_of_scope(self):
        from azinspect.waf.common import Findings
        from azinspect.waf.operations import governance
        tenant = 't0'
        children = [{'type': '/subscriptions', 'displayName': n} for n in ('pay-prod', 'ads-prod', 'lab-dev')]
        d = SimpleNamespace(mg={'detail': {tenant: {'value': {'displayName': 'Root', 'children': children}}}},
                            cfg=SimpleNamespace(tenant_id=tenant, include=['pay-prod'], exclude=[]),
                            enabled=[{'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}], subreads=[],
                            sub_env=lambda n: {'value': 'prod' if 'prod' in n else 'dev', 'label': '', 'basis': ''})
        out = Findings('operations')
        governance.check_management_groups(d, out, {}, 0)
        f = out.items[0]
        self.assertIn('3 个订阅直接挂在根管理组下', f['finding'])
        self.assertIn('pay-prod', f['finding'])
        self.assertNotIn('ads-prod', f['finding'])
        self.assertEqual([m['name'] for m in f['members']], ['pay-prod'])


class NarrativeIdTests(unittest.TestCase):
    def test_missing_ids_are_skipped_with_a_warning(self):
        # after an upgrade (or with a pillar left out) a narrative id no longer exists: 03/04 stopped half-way and 00
        # was not built; the id is now left out and the build says so
        from azinspect.waf.report import NarrativeError, apply_narrative
        findings = [{'id': 'R1-aaaaaa', 'severity': '中', 'finding': 'x'},
                    {'id': 'R2-cccccc', 'previousId': 'R2-old', 'severity': '低', 'finding': 'y'},
                    {'id': 'R2-dddddd', 'previousId': 'R2-old', 'severity': '低', 'finding': 'z'}]
        narrative = {'topIssues': [{'title': 'a', 'findingIds': ['R1-aaaaaa', 'S-I1-bbbbbb']}, {'title': 'b', 'findingIds': ['S-I1-bbbbbb']}],
                     'severityOverrides': [{'findingId': 'S-I1-bbbbbb', 'severity': '高', 'reason': 'r'}],
                     'findingTextOverrides': [{'findingId': 'R1-aaaaaa', 'finding': 'x2'}]}
        out, warnings = apply_narrative(findings, narrative)
        self.assertEqual([t['title'] for t in out['topIssues']], ['a'])
        self.assertEqual(out['topIssues'][0]['findingIds'], ['R1-aaaaaa'])
        self.assertEqual(findings[0]['finding'], 'x2')
        self.assertEqual(len(warnings), 4)                     # three ids, and the top issue dropped
        self.assertTrue(all('S-I1-bbbbbb' in w for w in warnings[:3]))
        self.assertIn('“b”', warnings[3])
        with self.assertRaises(NarrativeError):   # last month's id now split in two: the agent has to choose
            apply_narrative(findings, {'topIssues': [{'title': 'c', 'findingIds': ['R2-old']}]})


class AnalyzeFailureTests(unittest.TestCase):
    def test_a_failed_pillar_is_recorded_and_blocks_packaging(self):
        # analyze crashed in APRL after other pillars were rewritten; build, checks and package all passed with 03 short
        import tempfile
        from azinspect import package
        from azinspect.core import io
        from azinspect.waf import pipeline
        from azinspect.waf.common import Raw

        def module(pillar):
            def analyze(ws, cfg, log):
                if pillar == 'aprl':
                    raise TypeError("'NoneType' object is not subscriptable")
                return {'findings': []}
            return SimpleNamespace(analyze=analyze)
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            for p in ('reliability', 'aprl', 'defender'):
                Raw(ws, p).save('manifest.json', {})
            Raw(ws, 'aprl').save('results.json', {'results': []})
            said = []
            with mock.patch.object(pipeline, '_module', module):
                done = pipeline.analyze(ws, None, said.append, pillars=['reliability', 'aprl', 'defender'])
                self.assertEqual(done, ['reliability', 'defender'])                  # the others still ran
                self.assertTrue(any('aprl' in s and '失败' in s for s in said))
                self.assertTrue(any('aprl' in p for p in package.analysis_problems(ws)))
                with mock.patch.object(pipeline, '_module', lambda p: SimpleNamespace(analyze=lambda *a: {'findings': []})):
                    pipeline.analyze(ws, None, said.append, pillars=['aprl'])   # fixed and run again
                self.assertEqual(package.analysis_problems(ws), [])

    def test_aprl_without_results_is_skipped(self):
        import tempfile
        from azinspect.core import io
        from azinspect.waf import pipeline
        from azinspect.waf.common import Raw
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            Raw(ws, 'aprl').save('manifest.json', {})
            said = []
            self.assertEqual(pipeline.analyze(ws, None, said.append, pillars=['aprl']), [])
            self.assertTrue(any('没有' in s and 'aprl' in s for s in said))


class ExcelRecalcTests(unittest.TestCase):
    def run_excel(self, books, dispatch_errors=0):
        """Fake Excel over COM: Workbooks.Open hands out `books` in turn; DispatchEx fails `dispatch_errors` times first."""
        import tempfile
        from azinspect.core import excel as xl
        calls = {'dispatch': 0}

        def dispatch(name):
            calls['dispatch'] += 1
            if calls['dispatch'] <= dispatch_errors:
                raise OSError('Excel busy')
            app = SimpleNamespace(Visible=True, DisplayAlerts=True, AutomationSecurity=1, CalculationState=0,
                                  CalculateFullRebuild=lambda: None, Quit=lambda: None)
            app.Workbooks = SimpleNamespace(Open=lambda *a, **k: books.pop(0))
            return app
        client = SimpleNamespace(DispatchEx=dispatch)
        fake = {'pythoncom': SimpleNamespace(CoInitialize=lambda: None, CoUninitialize=lambda: None),
                'win32com': SimpleNamespace(client=client), 'win32com.client': client}
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as f:
            path = Path(f.name)
        try:
            with mock.patch.dict(sys.modules, fake), mock.patch.object(xl.platform, 'system', return_value='Windows'), \
                    mock.patch.dict(os.environ, {'AZINSPECT_NO_EXCEL': ''}), mock.patch.object(xl.time, 'sleep'):
                return xl._recalculate_with_excel(path), calls
        finally:
            path.unlink()

    def test_close_failing_after_save_counts(self):
        # a large 01 workbook was saved with Excel's values, then Close failed (AttributeError: Open.Close): the
        # recalculation was reported as failed and the audit fell back to the structure check
        def close(**k):
            raise AttributeError('Open.Close')
        saved = []
        book = SimpleNamespace(Save=lambda: saved.append(1), Close=close)
        (ok, reason), _calls = self.run_excel([book])
        self.assertEqual((ok, reason, saved), (True, None, [1]))

    def test_one_retry(self):
        book = SimpleNamespace(Save=lambda: None, Close=lambda **k: None)
        (ok, reason), calls = self.run_excel([book], dispatch_errors=1)
        self.assertEqual((ok, calls['dispatch']), (True, 2))


class CallRecordTests(unittest.TestCase):
    def test_retries_and_waits_are_recorded(self):
        # the call log kept only the last attempt: whether a slow query had been throttled could not be told
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"value": []}'
        tries = []

        def open_(req, timeout):
            tries.append(1)
            if len(tries) < 3:
                raise urllib.error.HTTPError(req.full_url, 429, 'Too Many Requests', {}, BytesIO(b''))
            return Response()
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda audience: 'token'), opener=SimpleNamespace(open=open_))
        with mock.patch.object(http.time, 'sleep'):
            client.get('/subscriptions?api-version=2022-12-01', 'test')
        record = client.calls[-1]
        self.assertEqual((record['status'], record['attempts'], record['waited'], record['throttled']), (200, 3, 6.0, 2))


class MatplotlibCacheTests(unittest.TestCase):
    def test_cache_in_the_workspace_when_the_default_is_not_writable(self):
        # in Codex's Windows sandbox neither the user profile nor TEMP is writable: build failed on the font cache, and the
        # agent may not set environment variables itself
        # (0.10.4 rc2 tested ~/.matplotlib and the TEMP root: matplotlib's default on Windows is %LOCALAPPDATA%\matplotlib,
        # and its fallback a new directory under TEMP, which the sandbox does not let it write into)
        from azinspect import cli
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MPLCONFIGDIR', None)
            cli._matplotlib_cache('C:/ws', default_ok=False)
            self.assertEqual(Path(os.environ['MPLCONFIGDIR']), Path('C:/ws') / '.cache' / 'matplotlib')
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MPLCONFIGDIR', None)
            cli._matplotlib_cache('C:/ws', default_ok=True)
            self.assertNotIn('MPLCONFIGDIR', os.environ)                     # the usual place works: left alone
        with mock.patch.dict(os.environ, {'MPLCONFIGDIR': 'D:/mine'}):
            cli._matplotlib_cache('C:/ws', default_ok=False)
            self.assertEqual(os.environ['MPLCONFIGDIR'], 'D:/mine')          # the user's own setting wins

    def test_default_dir_and_probe(self):
        import tempfile
        from azinspect import cli
        with tempfile.TemporaryDirectory() as home, mock.patch.object(cli.Path, 'home', return_value=Path(home)), \
                mock.patch.object(cli.platform, 'system', return_value='Windows'), mock.patch.dict(os.environ, {'LOCALAPPDATA': home + '/local'}):
            self.assertEqual(cli._mpl_default_dir(), Path(home) / 'local' / 'matplotlib')   # matplotlib's own default
            (Path(home) / '.matplotlib').mkdir()
            self.assertEqual(cli._mpl_default_dir(), Path(home) / '.matplotlib')            # an existing ~/.matplotlib wins
            probe = Path(home) / 'new' / 'matplotlib'
            self.assertTrue(cli._writable(probe))
            self.assertFalse(probe.exists())    # a directory made for the test is removed: it would change matplotlib's choice

    def test_management_groups_none_chosen_wording(self):
        # "本次所选订阅中有 0 个" read stiffly
        from azinspect.waf.common import Findings
        from azinspect.waf.operations import governance
        children = [{'type': '/subscriptions', 'displayName': n} for n in ('ads-prod', 'lab-dev')]
        d = SimpleNamespace(mg={'detail': {'t0': {'value': {'displayName': 'Root', 'children': children}}}},
                            cfg=SimpleNamespace(tenant_id='t0', include=['pay-prod'], exclude=[]),
                            enabled=[{'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}], subreads=[],
                            sub_env=lambda n: {'value': 'prod' if 'prod' in n else 'dev', 'label': '', 'basis': ''})
        out = Findings('operations')
        governance.check_management_groups(d, out, {}, 0)
        self.assertIn('本次所选的订阅都不在其中', out.items[0]['finding'])


class ErrorTextTests(unittest.TestCase):
    def error_for(self, body):
        def open_(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 400, 'Bad Request', {}, BytesIO(body))
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda audience: 'token'), opener=SimpleNamespace(open=open_))
        with mock.patch.object(http.time, 'sleep'):
            return client.get('/subscriptions?api-version=2022-12-01', 'test')[2]

    def test_error_keys_in_any_case(self):
        # the activity log answers {"Code": ..., "Message": ...}: recorded as "None: None"
        self.assertEqual(self.error_for(b'{"Code": "BadRequest", "Message": "start time too old"}'), 'BadRequest: start time too old')
        self.assertEqual(self.error_for(b'{"error": {"code": "X", "message": "y"}}'), 'X: y')
        self.assertIn('plain text', self.error_for(b'plain text answer'))
        self.assertNotIn('None', self.error_for(b'{"something": "else"}'))


if __name__ == '__main__':
    unittest.main()
