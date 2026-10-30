"""Customer wording for VM recommendations: rule outcomes and reasons turned into plain Chinese."""
from __future__ import annotations

import re

STATUS = {
    '建议试点调整': '建议调整（先小范围试用）',
    '已释放：不计持续计算降配节省': '已停机，不更换规格',
    '保持现状：平均利用率不低': '保持原规格：CPU和内存均不低于20%',
    '保持现状：网络设备': '网络设备：不建议调整规格',
    '保持现状：无对应一档规格': '保持原规格：没有合适的较小规格',
    '保持现状：目标条件不满足': '暂不调整：见备注',
    '数据不足：暂不能判断': '数据不足，暂不判断',
    '暂不调整：整池条件未满足': '暂不调整：同池机器不能统一更换',
    '保持现状：该系列未制定降档规则': '保持原规格：该系列需单独评估',
    '状态未确认释放：暂不能判断': '电源状态未确认，暂不判断',
}
DIRECTION = {
    'CPU与内存减半': 'CPU核数和内存容量都减半',
    '只减CPU，内存保留': 'CPU核数减半，内存容量不变',
    '只减内存，CPU保留': '内存容量减半，CPU核数不变',
}
_DENIED = re.compile(r'HTTP\s*403|AuthorizationFailed|checkAccess/read', re.I)


def direction_text(direction):
    return DIRECTION.get(direction, direction)


def metric_errors(record, vm):
    return record.get('metricErrors') or {name: m['error'] for name, m in (vm or {}).get('metrics', {}).items() if m.get('error')}


def denied(record, vm) -> bool:
    return any(_DENIED.search(str(error)) for error in metric_errors(record, vm).values())


def status_text(record, vm=None):
    if record['status'] == '数据不足：暂不能判断':
        if denied(record, vm):
            return '读取权限不足，暂不判断'
        if vm and any(vm.get('metrics', {}).get(name, {}).get('validDays', 0) < 7 for name in ['Percentage CPU', 'Available Memory Percentage']):
            return '有效数据不足7天，暂不判断'
    return STATUS.get(record['status'], record['status'])


def _blocker(text):
    if '未对该系列制定降档规则' in text:
        return '该系列需要单独评估性能，暂不建议更换'
    if text.startswith('目标可用区部署限制需复核：'):
        return '目标规格在可用区' + text.split('：', 1)[1] + '受限，需要确认部署位置'
    if '临时盘容量减少' in text:
        return '目标临时盘更小，需要确认本地数据能否放下'
    if '可挂数据盘数不足' in text:
        return '目标规格不能挂载现有数量的数据盘'
    if 'NIC数量上限不足' in text:
        return '目标规格支持的网卡数量不足'
    if '目标官网价格未低于' in text:
        return '目标规格没有更便宜'
    if '官网' in text and ('单价缺失' in text or '未匹配' in text):
        return '没有找到匹配的官网列表价'
    if 'SKU能力未匹配' in text:
        return '缺少当前规格的性能上限信息'
    if '同池其他节点' in text:
        return '同池其他机器不能统一更换为同一种规格'
    if '指标或限额缺失' in text or '采样不足' in text:
        return '缺少足够的用量数据或规格上限信息'
    text = text.replace('投影', '预计值').replace('无法校核', '无法判断').replace('本轮', '').replace('本次', '')
    return text.replace('目标VM级磁盘平均消耗率', '更换后VM磁盘平均消耗率')


def customer_note(record, vm, pool_name=None):
    state = str(record.get('state', '')).lower()
    candidate = record.get('candidate') or {}
    result = []
    if state == 'powerstate/deallocated':
        result.append('计算费已停止；保留的磁盘和IP仍可能收费')
    elif record['status'] == '建议试点调整':
        result.append(direction_text(candidate['direction']))
        result.append('平均用量和VM磁盘性能满足要求，列表价更低')
    elif record['status'] == '保持现状：无对应一档规格':
        cpu, memory = record.get('cpuAverage'), record.get('memoryAverage')
        if cpu is not None and memory is not None and cpu < 20 <= memory:
            result.append('未找到CPU核数减半、内存容量和所需功能不变的规格')
        elif cpu is not None and memory is not None and memory < 20 <= cpu:
            result.append('未找到内存减半、CPU核数和所需功能不变的规格')
        else:
            result.append('没有找到容量更小且保留所需功能的规格')
    elif record['status'] == '保持现状：平均利用率不低':
        result.append('CPU和内存平均利用率均不低于20%')
    elif record['status'] == '数据不足：暂不能判断':
        if not denied(record, vm):
            days = min(vm.get('metrics', {}).get(name, {}).get('validDays', 0) for name in ['Percentage CPU', 'Available Memory Percentage'])
            result.append(f'CPU/内存只有{days}天有效数据，需补足7天' if days < 7 else 'CPU/内存采样不足，或规格/价格信息不完整')
        if any('未对该系列' in x for x in record.get('reasons', [])):
            result.append('该系列需要单独评估性能，暂不建议更换')
    else:
        for reason in record.get('reasons', []):
            if any(t in reason for t in ['拟减少的容量', 'CPU与内存减半', '只减CPU', '只减内存', '同池全部运行节点通过', '缺失不补0']):
                continue
            result.extend(_blocker(part) for part in reason.split('；') if part)
    if denied(record, vm):
        result.append('指标读取权限不足（HTTP403），无法判断利用率')
    if vm.get('plan'):
        result.append('报价不含Marketplace软件许可费，需另行确认')
    if pool_name:
        result.append(('VMSS ' if record['kind'] == 'vmss' else 'AKS节点池 ') + pool_name + '：所有运行VM须一起调整')
    if candidate and record['status'] != '建议试点调整':
        result.append('暂不更换为 ' + candidate['sku'])
    if state not in ('powerstate/running', 'powerstate/deallocated'):
        result.append('电源状态未确认，暂不估算持续计算费用')
    if state == 'powerstate/running' and any(record.get(k) is None for k in ['currentCores', 'currentMemoryGiB']):
        result.append('缺少当前规格的容量信息')
    return '；'.join(dict.fromkeys(result))
