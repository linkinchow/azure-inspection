"""Delivery package: <客户>_Azure巡检报告_<出具月份>/ folder + zip with the 00-05 reports and the charts they reference.

Checks before writing (any failure stops the package):
- only 00 and the reports chosen this month (findings/selection.json) are packed, and every chosen one must exist;
- every Markdown passes quality-check, every chart a Markdown links to exists;
- crosscheck has run and has no rule left at '需要处理' unless --allow-open is given (the agent then reports them);
Checks after writing: byte-for-byte copy, zip test, zip contents equal to the folder, no Excel lock files.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import zipfile
from pathlib import Path

from .core.io import read_json, write_json
from .core.quality import check_markdown, check_narratives
from .selection import TITLES, load as load_selection

REPORT = re.compile(r'^0[0-5]_.+\.(md|xlsx)$')
IMAGE = re.compile(r'!\[[^\]]*\]\((charts/[^)]+)\)')


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(ws) -> dict:
    """Fingerprints of the report files before a build."""
    reports = ws.month_dir('reports')
    if not reports.exists():
        return {}
    out = {p.name: _sha(p) for p in reports.iterdir() if p.is_file() and REPORT.match(p.name)}
    out.update({f'charts/{p.name}': _sha(p) for p in (reports / 'charts').glob('*.png')})
    return out


def record_build(ws, started: float, before: dict | None = None, codes=()) -> None:
    """Fingerprint the report files this build wrote, so packaging can tell when one was edited by hand afterwards:
    those modified since the build started, and those whose content changed (Excel's save can leave an older time)."""
    reports = ws.month_dir('reports')
    path = ws.month_dir('findings') / 'build-hashes.json'
    hashes = read_json(path) if path.exists() else {}
    for p in reports.iterdir():
        if not (p.is_file() and REPORT.match(p.name)):
            continue
        sha = _sha(p)
        if p.stat().st_mtime >= started - 1 or (before is not None and before.get(p.name) != sha):
            hashes[p.name] = sha
    # charts this build drew, with the results they were drawn from (X9 trusts this over file times): every chart of a
    # report built now (build clears and redraws them; a redrawn chart can be byte-identical with an old file time)
    from .crosscheck import chart_sources
    charts, drawn = reports / 'charts', hashes.setdefault('_charts', {})
    for p in sorted(charts.glob('*.png')) if charts.exists() else []:
        sha = _sha(p)
        if p.name[:2] in codes or p.stat().st_mtime >= started - 1 or (before is not None and before.get(f'charts/{p.name}') != sha):
            drawn[p.name] = [sha, chart_sources(ws, p.name[:2])]
    for name in [n for n in drawn if not (charts / n).exists()]:
        del drawn[name]
    write_json(path, hashes)


def build(ws, cfg, period, allow_open=False, log=print):
    reports = ws.month_dir('reports')
    files = sorted(p for p in reports.iterdir() if p.is_file() and REPORT.match(p.name) and not p.name.startswith('~$'))
    if not files:
        raise SystemExit('reports/ 下没有报告文件，先运行 build')
    chosen = ('00',) + tuple(load_selection(ws))
    left_out = sorted({p.name[:2] for p in files if p.name[:2] not in chosen})
    if left_out:
        log(f'本月未选择 {"、".join(left_out)}：reports/ 里这些报告的旧文件不打包')
    files = [p for p in files if p.name[:2] in chosen]
    problems = [f'所选报告 {c} {TITLES.get(c, "汇总")} 还没有生成，先运行 build' for c in chosen if not any(p.name.startswith(f'{c}_') for p in files)]
    charts = set()
    for md in (p for p in files if p.suffix == '.md'):
        problems += [f'{md.name}：{x}' for x in check_markdown(md)]
        for rel in IMAGE.findall(md.read_text(encoding='utf-8')):
            if not (reports / rel).exists():
                problems.append(f'{md.name}：图片不存在 {rel}')
            charts.add(rel)
    problems += [f'说明文件：{x}' for x in check_narratives(ws.month_dir())]
    hashes_path = ws.month_dir('findings') / 'build-hashes.json'
    hashes = read_json(hashes_path) if hashes_path.exists() else None
    for f in files if hashes is not None else []:
        if hashes.get(f.name) != _sha(f):
            problems.append(f'{f.name}：生成后被手工修改过，或不是 build 生成的。要改文字，请改 narrative/*.json 后重新 build')
    cross = ws.month_dir('findings') / 'crosscheck.json'
    if not cross.exists():
        problems.append('还没有运行 crosscheck')
    else:
        open_rules = [r['rule'] for r in read_json(cross)['rules'] if r['status'] == '需要处理']
        if open_rules and not allow_open:
            problems.append(f'交叉核对还有未处理的规则：{"、".join(open_rules)}（处理后重跑 crosscheck；确认只加提醒的，用 --allow-open 打包并告诉用户）')
    if problems:
        for p in problems:
            log(f'  - {p}')
        raise SystemExit(f'打包前检查未通过：{len(problems)} 处')
    name = f'{cfg.file_name}_Azure巡检报告_{period.following.label}'
    root = ws.month_dir('package')
    folder, archive = root / name, root / f'{name}.zip'
    if folder.exists():
        shutil.rmtree(folder)
    (folder / 'charts').mkdir(parents=True)
    copied = []
    for src in files + [reports / rel for rel in sorted(charts)]:
        dest = folder / src.relative_to(reports)
        shutil.copy2(src, dest)
        copied.append((src, dest))
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for _, dest in copied:
            z.write(dest, f'{name}/{dest.relative_to(folder).as_posix()}')
    errors = [f'{d.name} 与源文件不一致' for s, d in copied if _sha(s) != _sha(d)]
    with zipfile.ZipFile(archive) as z:
        bad = z.testzip()
        if bad:
            errors.append(f'压缩包损坏：{bad}')
        names = sorted(n for n in z.namelist() if not n.endswith('/'))
        expected = sorted(f'{name}/{d.relative_to(folder).as_posix()}' for _, d in copied)
        if names != expected:
            errors.append('压缩包内容与文件夹不一致')
        for _, dest in copied:
            if z.read(f'{name}/{dest.relative_to(folder).as_posix()}') != dest.read_bytes():
                errors.append(f'压缩包中的 {dest.name} 与文件夹不一致')
    if any(p.name.startswith('~$') for p in folder.rglob('*')):
        errors.append('包含 Excel 锁文件')
    if errors:
        raise SystemExit('打包核对未通过：' + '；'.join(errors))
    manifest = {'folder': str(folder), 'zip': str(archive), 'files': [{'name': d.relative_to(folder).as_posix(), 'sha256': _sha(d)} for _, d in copied]}
    write_json(root / 'package-manifest.json', manifest)
    log(f'打包完成：{len(files)} 个报告文件、{len(charts)} 张图表')
    log(f'  文件夹：{folder}')
    log(f'  压缩包：{archive}')
    return manifest
