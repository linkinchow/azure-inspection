"""Checks every customer-facing Markdown file must pass before packaging.

Each check comes from a problem a customer or reviewer actually hit in an earlier engagement:
literal ** in rendered text, missing chart files, tables with a wrong column count, internal
process wording, e-mail addresses.
"""
from __future__ import annotations

import re
from pathlib import Path

# Internal process words that must not reach a customer document (see references/writing-style.md).
BANNED = ['旧报告', '本轮', '样板', '内部核验', '口径', '校核', '潜在收益', '可落地', '见表后说明', 'TODO', 'FIXME', 'TBD']
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z.]{2,}')
_SEPARATOR = re.compile(r'^\|\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|\s*$')


def _cells(line: str) -> int:
    return line.replace('\\|', '').strip().strip('|').count('|') + 1


def check_markdown(path: Path, banned: list[str] | None = None) -> list[str]:
    from markdown_it import MarkdownIt

    text = path.read_text(encoding='utf-8')
    issues = []
    rendered = re.sub(r'<[^>]+>', '', MarkdownIt('commonmark').enable('table').render(text))
    if '**' in rendered:
        issues.append(f'渲染后仍有 {rendered.count("**")} 处 ** 显示成星号（粗体两侧的标点要放在星号外面）')
    for ref in re.findall(r'!\[[^\]]*\]\(([^)\s]+)\)', text):
        if not ref.startswith(('http://', 'https://')) and not (path.parent / ref).exists():
            issues.append(f'图片不存在：{ref}')
    for ref in re.findall(r'(?<!!)\[[^\]]*\]\(([^)#\s]+)\)', text):
        if not ref.startswith(('http://', 'https://', 'mailto:')) and not (path.parent / ref).exists():
            issues.append(f'链接的文件不存在：{ref}')
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('|') and i + 1 < len(lines) and _SEPARATOR.match(lines[i + 1]):
            expected, j = _cells(line), i + 2
            while j < len(lines) and lines[j].startswith('|'):
                if _cells(lines[j]) != expected:
                    issues.append(f'第 {j + 1} 行表格列数为 {_cells(lines[j])}，表头为 {expected}')
                j += 1
    for word in banned if banned is not None else BANNED:
        for m in re.finditer(re.escape(word), text):
            issues.append(f'内部用语“{word}”：…{text[max(0, m.start() - 15):m.end() + 15]}…'.replace('\n', ' '))
    for email in sorted(set(_EMAIL.findall(text))):
        issues.append(f'包含邮箱地址：{email[:3]}…')
    return issues


def check_tree(root: Path) -> dict[str, list[str]]:
    results = {}
    for md in sorted(Path(root).rglob('*.md')):
        issues = check_markdown(md)
        if issues:
            results[str(md.relative_to(root))] = issues
    return results
