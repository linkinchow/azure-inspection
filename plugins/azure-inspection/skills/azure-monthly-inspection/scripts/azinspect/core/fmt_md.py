"""Chinese/English spacing and bold-marker fixes for customer Markdown. Numbers, links and code are never changed."""
from __future__ import annotations

import re

CJK = r'㐀-䶿一-鿿'


def format_prose(text: str) -> str:
    replacements = {
        'VMRI': 'VM RI', 'PremiumSSD': 'Premium SSD', 'RetailAPI': 'Retail API', 'ResourceGraph': 'Resource Graph',
        'RI1/3': 'RI 1/3', 'SP1/3': 'SP 1/3', 'provisionedv2': 'provisioned v2',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r'(\d)(running|deallocated|nodes?|TiB|GiB|IOPS|MBps|USD|vCore|provisioned)(?=\b|[' + CJK + r'])', r'\1 \2', text)
    text = re.sub(r'([' + CJK + r'])([A-Za-z0-9])', r'\1 \2', text)
    text = re.sub(r'([A-Za-z0-9])([' + CJK + r'])', r'\1 \2', text)
    text = re.sub(r'(?<=[A-Za-z0-9' + CJK + r'])\s*([×＝≠≤÷＋])\s*(?=[A-Za-z0-9' + CJK + r'])', r' \1 ', text)
    text = re.sub(r'(?<=[A-Za-z0-9])\s*=\s*(?=[A-Za-z0-9])', ' = ', text)
    text = re.sub(r'([，。；：、])\s+(?=[^\s])', r'\1', text)
    return fix_bold(text)


def fix_bold(text: str) -> str:
    """Move punctuation at the edges of **bold** outside the markers.

    CommonMark does not close '**' that follows punctuation when the next character is a
    letter (e.g. '**…节点。**子网'), so the asterisks would show literally.
    """
    def move(match):
        inner = match.group(1)
        if len(inner) > 2 and inner[0] in '（(' and inner[-1] in '）)' and not re.search(r'[（()）]', inner[1:-1]):
            return f'{inner[0]}**{inner[1:-1]}**{inner[-1]}'
        lead = re.match(r'^[【「『“‘]+', inner)
        head = lead.group(0) if lead else ''
        rest = inner[len(head):]
        trail = re.search(r'[。．，、；：！？】」』”’]+$', rest)
        tail = trail.group(0) if trail else ''
        core = rest[:len(rest) - len(tail)]
        if core[-1:] in '）)' and not re.search(r'[（(]', core):
            tail, core = core[-1] + tail, core[:-1]
        return f'{head}**{core}**{tail}' if core else match.group(0)
    return re.sub(r'\*\*([^*\n]+?)\*\*', move, text)


def format_markdown(text: str) -> str:
    output, fenced = [], False
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith(('```', '~~~')):
            fenced = not fenced
            output.append(line)
            continue
        if fenced:
            output.append(line)
            continue
        protected = []

        def protect(match):
            protected.append(match.group(0))
            token = '\x00' + str(len(protected) - 1) + '\x00'
            if match.group(0).startswith('`'):
                if match.start() and re.match('[' + CJK + ']', match.string[match.start() - 1]):
                    token = ' ' + token
                if match.end() < len(match.string) and re.match('[' + CJK + ']', match.string[match.end()]):
                    token += ' '
            return token

        line = re.sub(r'`+[^`\n]*`+|\]\([^\n]*?\)|https?://[^\s)]+', protect, line)
        line = format_prose(line)
        for index, value in enumerate(protected):
            line = line.replace('\x00' + str(index) + '\x00', value)
        output.append(line)
    return ''.join(output)


def validate_formatting(before: str, after: str) -> None:
    """Formatting must never change URLs, numbers, inline code or link targets."""
    urls = lambda v: re.findall(r'https?://[^\s)]+', v)
    numbers = lambda v: re.findall(r'\d+(?:[,.]\d+)*', v)
    code = lambda v: re.findall(r'`+[^`\n]*`+', v)
    links = lambda v: re.findall(r'\]\([^\n]*?\)', v)
    assert urls(before) == urls(after), 'Source URLs changed'
    assert numbers(before) == numbers(after), 'Numeric content changed'
    assert code(before) == code(after), 'Inline identifiers changed'
    assert links(before) == links(after), 'Markdown link targets changed'


def format_and_check(text: str) -> str:
    after = format_markdown(text)
    validate_formatting(text, after)
    return after
