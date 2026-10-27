"""Delivery package: <客户>_Azure巡检报告_<出具月份>/ folder + zip with the 00-05 reports and the charts they reference.

Checks before writing (any failure stops the package):
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
from .core.quality import check_markdown

REPORT = re.compile(r'^0[0-5]_.+\.(md|xlsx)$')
IMAGE = re.compile(r'!\[[^\]]*\]\((charts/[^)]+)\)')


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(ws, cfg, period, allow_open=False, log=print):
    reports = ws.month_dir('reports')
    files = sorted(p for p in reports.iterdir() if p.is_file() and REPORT.match(p.name) and not p.name.startswith('~$'))
    if not files:
        raise SystemExit('reports/ 下没有报告文件，先运行 build')
    problems = []
    charts = set()
    for md in (p for p in files if p.suffix == '.md'):
        problems += [f'{md.name}：{x}' for x in check_markdown(md)]
        for rel in IMAGE.findall(md.read_text(encoding='utf-8')):
            if not (reports / rel).exists():
                problems.append(f'{md.name}：图片不存在 {rel}')
            charts.add(rel)
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
