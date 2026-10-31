"""Resource Graph queries are well formed offline: a column projected twice makes Resource Graph answer 400 BadRequest."""
from __future__ import annotations

import importlib
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SOURCES = {'azinspect.waf.operations.collect': ['ARG_Q'], 'azinspect.waf.performance.collect': ['ARG_QUERIES'],
           'azinspect.waf.reliability.collect': ['ARG_QUERIES'], 'azinspect.waf.security_identity.collect': ['QUERIES'],
           'azinspect.waf.security_network.collect': ['ARG_TYPES', 'PE_QUERY']}


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from strings(v)


def top_level(text, sep):
    """Split at `sep` outside brackets and quotes."""
    parts, depth, quote, cur = [], 0, None, ''
    for ch in text:
        if quote:
            quote = None if ch == quote else quote
        elif ch in '\'"':
            quote = ch
        elif ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(cur)
            cur = ''
            continue
        cur += ch
    return parts + [cur]


def projected(query):
    """Column names of each `project` step (not project-away / project-rename)."""
    out = []
    for step in top_level(query, '|'):
        m = re.match(r'\s*project\s+(.*)$', step, re.S)
        if not m:
            continue
        names = []
        for col in top_level(m.group(1), ','):
            col = col.strip()
            head = top_level(col, '=')[0].strip() if re.match(r'^\w+\s*=[^=]', col) else col
            names.append(head)
        out.append(names)
    return out


class QueryTests(unittest.TestCase):
    def test_no_column_projected_twice(self):
        checked = 0
        for module, names in SOURCES.items():
            mod = importlib.import_module(module)
            for name in names:
                for q in strings(getattr(mod, name)):
                    for cols in projected(q):
                        checked += 1
                        dup = sorted({c for c in cols if cols.count(c) > 1})
                        self.assertEqual(dup, [], f'{module}.{name}: {dup} projected twice in: {q[:120]}')
        self.assertGreater(checked, 20)


if __name__ == '__main__':
    unittest.main()
