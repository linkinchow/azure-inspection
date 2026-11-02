"""Narrative files written for another choice of reports or pillars (synthetic data): after "只做可靠性" and back,
the agents built the full 00/03 from the reliability-only narratives, and every check passed."""
from __future__ import annotations

import contextlib
import io as stdio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import selection  # noqa: E402
from azinspect.core import io  # noqa: E402

ALL = ('01', '02', '03', '04', '05')


class NarrativeChoiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = io.Workspace(self.tmp.name, '2026-09')
        self.ws.create()
        for code in ('00', '03', '04'):
            self.write(code, f'{code} 全部')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, code, text):
        io.write_json(self.ws.month_dir('narrative') / f'{code}.json', {'conclusion': [text]})

    def stale(self, reports, groups=None):
        return [name for name, _was in selection.stale_narratives(self.ws, reports, groups)]

    def test_unchanged_narratives_under_another_choice(self):
        self.assertEqual(self.stale(ALL), [])                     # never built: nothing to compare
        selection.stamp_narratives(self.ws, ALL)
        self.assertEqual(self.stale(ALL), [])
        self.assertEqual(self.stale(('03',), ('可靠性',)), ['00.json', '03.json'])   # 04 not chosen: not read
        self.write('00', '00 只做可靠性')
        self.write('03', '03 只做可靠性')
        self.assertEqual(self.stale(('03',), ('可靠性',)), [])    # rewritten for the new choice
        selection.stamp_narratives(self.ws, ('03',), ('可靠性',))
        self.assertEqual(self.stale(ALL), ['00.json', '03.json'])  # back to everything with the reliability-only text

    def test_choice_that_does_not_touch_a_narrative(self):
        selection.stamp_narratives(self.ws, ALL)
        # 05 left out: 00 summarises less, 03 and 04 cover the same pillars
        self.assertEqual(self.stale(('01', '02', '03', '04')), ['00.json'])

    def test_explain_what_it_was_written_for(self):
        selection.stamp_narratives(self.ws, ('03',), ('可靠性',))
        (name, was), = [x for x in selection.stale_narratives(self.ws, ALL) if x[0] == '03.json']
        self.assertIn('可靠性', was)


class BuildStopsTests(unittest.TestCase):
    def test_narrative_error_is_explained_not_a_traceback(self):
        # with --narrative-checked, 03.json still pointing at problems of a pillar left out crashed with a traceback
        from azinspect import cli
        from azinspect.core import config
        import azinspect.waf.pipeline
        from azinspect.waf.report import NarrativeError

        def fail(*a, **k):
            raise NarrativeError('说明文件引用的问题编号不存在：S-I1-aaaaaa')
        out = stdio.StringIO()
        with (tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out),
              mock.patch.object(config, 'load', return_value=SimpleNamespace(reports=('03',), groups=('可靠性',))),
              mock.patch.object(azinspect.waf.pipeline, 'build', fail)):
            code = cli.main(['build', '--workspace', d, '--month', '2026-09', '--part', 'waf', '--narrative-checked'])
        self.assertEqual(code, 2)
        self.assertIn('S-I1-aaaaaa', out.getvalue())
        self.assertIn('改写', out.getvalue())


if __name__ == '__main__':
    unittest.main()
