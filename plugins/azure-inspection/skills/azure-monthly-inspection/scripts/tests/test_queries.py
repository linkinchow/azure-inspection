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


class CoverageNoteTests(unittest.TestCase):
    """Coverage notes reach the customer's Excel (检查覆盖): plain Chinese, no English sentences, file names or commit ids."""

    @staticmethod
    def text_of(node):
        """A note as the customer reads it: f-string values stand in as 1."""
        import ast
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return ''.join(v.value if isinstance(v, ast.Constant) else '1' for v in node.values)
        if isinstance(node, ast.BinOp):
            return (CoverageNoteTests.text_of(node.left) or '') + (CoverageNoteTests.text_of(node.right) or '')
        return None

    @staticmethod
    def note_texts(tree):
        """Every note appended, inserted, extended or written as 'notes': [...]."""
        import ast

        def is_notes(node):
            return (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value == 'notes') or \
                   (isinstance(node, ast.Name) and node.id == 'notes')
        for node in ast.walk(tree):
            values = []
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('append', 'extend', 'insert')
                    and is_notes(node.func.value)):
                values = node.args[-1:]
            elif isinstance(node, ast.AugAssign) and is_notes(node.target):
                values = [node.value]
            elif isinstance(node, ast.Dict):
                values = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == 'notes']
            for value in values:
                items = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
                for item in items:
                    for sub in [item] + [x for x in ast.walk(item) if isinstance(x, (ast.JoinedStr, ast.Constant))]:
                        text = CoverageNoteTests.text_of(sub)
                        if text:
                            yield node.lineno, text

    def test_no_english_or_internal_details(self):
        import ast
        english = re.compile(r'(?:\b[A-Za-z0-9][\w/().,;:+-]*\s+){4,}[A-Za-z]')   # four or more English words (or numbers) in a row
        bad = []
        for path in sorted((Path(__file__).resolve().parents[1] / 'azinspect' / 'waf').rglob('*.py')):
            for line, text in self.note_texts(ast.parse(path.read_text(encoding='utf-8'))):
                if english.search(text) or '.json' in text or '提交' in text:
                    bad.append(f'{path.parent.name}/{path.name}:{line}: {text[:80]}')
        self.assertEqual(sorted(set(bad)), [])
