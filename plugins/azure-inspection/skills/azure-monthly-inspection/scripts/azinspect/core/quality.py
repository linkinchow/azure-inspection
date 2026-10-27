"""Checks every customer-facing Markdown file must pass before packaging.

Each check comes from a problem a customer or reviewer actually hit in an earlier engagement:
literal ** in rendered text, missing chart files, tables with a wrong column count, internal
process wording, e-mail addresses.
"""
from __future__ import annotations

import re
from pathlib import Path

# Internal process words that must not reach a customer document (see references/writing-style.md).
BANNED = ['旧报告', '本轮', '样板', '内部核验', '口径', '校核', '潜在收益', '可落地', '见表后说明', 'TODO', 'FIXME', 'TBD',
          '跨报告', '交叉核对', '命中', '未自行', '属性筛选', '说明文件']
# Hedging that buries the recommendation. Calibrated on accepted reports (at most ~5 per 10,000 characters, no
# repeated confirmation clause) against an unedited agent draft (9-20 per 10,000 characters, 7-17 confirmation clauses).
CONFIRM = re.compile(r'需(?:要)?客户确认后(?:再)?执行')
CONFIRM_MAX = 2
HEDGES = ['不等于', '不代表', '不能据此', '尚不能', '不能仅', '断言', '不能把', '不能将', '不能用', '不能由', '不能按', '不作为', '不能直接',
          '不能视为', '不能认定', '不能推定', '不推定', '不能当作']
HEDGE_MIN, HEDGE_PER_10K = 5, 6
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
    confirms = len(CONFIRM.findall(text))
    if confirms > CONFIRM_MAX:
        issues.append(f'“需客户确认后执行”出现 {confirms} 次：在处理顺序或范围说明里写一次即可')
    hedges = {w: text.count(w) for w in HEDGES if w in text}
    limit = max(HEDGE_MIN, int(len(text) * HEDGE_PER_10K / 10000))
    if sum(hedges.values()) > limit:
        top = '、'.join(f'“{w}”{n} 次' for w, n in sorted(hedges.items(), key=lambda kv: -kv[1])[:4])
        issues.append(f'否定和保留说法太多（{sum(hedges.values())} 处，上限 {limit} 处）：{top}。先写建议，限制只写一次')
    for email in sorted(set(_EMAIL.findall(text))):
        issues.append(f'包含邮箱地址：{email[:3]}…')
    return issues


def _finding_names(month_dir: Path) -> tuple[dict[str, set[str]], set[str]]:
    """Resource and subscription names per finding id, and the names of the high-severity findings."""
    import json
    names, high = {}, set()
    for path in (month_dir / 'findings' / 'waf').glob('*.json'):
        data = json.loads(path.read_text(encoding='utf-8'))
        for f in data.get('findings', []) if isinstance(data, dict) else []:
            raw = [m.get('name') or '' for m in f.get('members') or []]
            raw += [f.get('resourceName') or '', f.get('subscriptionName') or f.get('subscription') or '']
            found = {re.sub(r'^(VM|VMSS)\s+', '', n.strip()) for r in raw for n in re.split(r'[、,，/]', r)}
            names[f['id']] = {n for n in found if len(n) >= 3 and not n.startswith('(') and not re.search(r'\d+\s*个', n)}
            if f.get('severity') == '高':
                high |= {n for n in found if len(n) >= 3 and not n.startswith('(') and not re.search(r'\d+\s*个', n)}
    return names, high


def check_narratives(month_dir: Path) -> list[str]:
    """The issues a reader sees first (00 immediate, 03/04 top issues) must name the resources or subscriptions they are about."""
    import json
    narrative_dir = Path(month_dir) / 'narrative'
    names, high = _finding_names(Path(month_dir))
    issues = []
    summary = narrative_dir / '00.json'
    conclusion = ''.join(json.loads(summary.read_text(encoding='utf-8')).get('conclusion') or []) if summary.exists() else ''
    if conclusion:
        if 'USD' not in conclusion:
            issues.append('00 结论没有写金额：要写费用变化和主要原因、预计节省（时间范围和数据来源脚本已写，不要重复）')
        if high and not any(n in conclusion for n in high):
            issues.append(f'00 结论没有点名最需要处理的资源（例如 {"、".join(sorted(high)[:3])}）')
    for report, key in (('00', 'immediate'), ('03', 'topIssues'), ('04', 'topIssues')):
        path = narrative_dir / f'{report}.json'
        if not path.exists():
            continue
        items = json.loads(path.read_text(encoding='utf-8')).get(key) or []
        missing = [str(i) for i, item in enumerate(items, 1) if not item.get('impact')]
        if missing and len(missing) < len(items):
            issues.append(f'{report} 第 {"、".join(missing)} 条缺少“影响”：要么每条都写，要么都不写（表格会出现空格）')
        for i, item in enumerate(items, 1):
            expected = set().union(*(names.get(fid, set()) for fid in item.get('findingIds') or [])) if item.get('findingIds') else set()
            text = f"{item.get('title', '')}{item.get('detail', '')}"
            if expected and not any(n in text for n in expected):
                sample = '、'.join(sorted(expected)[:3])
                issues.append(f'{report} 第 {i} 条“{item.get("title", "")}”没有点名具体资源或订阅（例如 {sample}）')
    return issues


def check_tree(root: Path) -> dict[str, list[str]]:
    results = {}
    for md in sorted(Path(root).rglob('*.md')):
        issues = check_markdown(md)
        if issues:
            results[str(md.relative_to(root))] = issues
    root = Path(root)
    if root.name == 'reports' and (root.parent / 'narrative').is_dir():
        issues = check_narratives(root.parent)
        if issues:
            results['narrative（说明文件）'] = issues
    return results
