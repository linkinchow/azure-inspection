"""Tests for the checked-in sample reports (examples/sample-output, invented customer): 00 says the same numbers as its own table."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

SAMPLE = Path(__file__).resolve().parents[6] / 'examples' / 'sample-output'
AMOUNT = re.compile(r'USD\s*[\d,]+\.\d{2}|[+-]?\d+\.\d+%')


class SampleSummaryTests(unittest.TestCase):
    def test_conclusion_numbers_match_the_table(self):
        reports = sorted(SAMPLE.glob('*/00_*.md'))
        if not reports:
            self.skipTest('no sample output in this checkout')
        text = reports[0].read_text(encoding='utf-8')
        section = text.split('\n## 1. ', 1)[1].split('\n## 2. ', 1)[0]
        table = '\n'.join(x for x in section.splitlines() if x.startswith('|'))
        prose = '\n'.join(x for x in section.splitlines() if not x.startswith('|'))
        stray = [m for m in AMOUNT.findall(prose) if m.replace(' ', '') not in table.replace(' ', '')]
        self.assertEqual(stray, [], '00 结论段落里的金额或百分比与第 1 节表格不一致')


if __name__ == '__main__':
    unittest.main()
