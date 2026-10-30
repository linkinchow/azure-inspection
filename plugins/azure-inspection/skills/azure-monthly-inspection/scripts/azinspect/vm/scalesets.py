"""Scale set instances that are already counted as virtual machines.

The inventory reads virtual machines and, from ComputeResources, scale set instances. In a Flexible scale set every
instance is also a standalone virtual machine resource, so the same machine appeared twice: once as the VM (with power
state and metrics) and once as an empty instance row (no properties, no power state, no metrics). Uniform scale set
instances are not VM resources and are kept. An instance of a Flexible scale set without a matching VM was usually
deleted by autoscale after the inventory snapshot; it is counted apart, not shown as "power state unknown".
"""
from __future__ import annotations

VM_TYPE = 'microsoft.compute/virtualmachines'
VMSS_TYPE = 'microsoft.compute/virtualmachinescalesets'


def drop_flexible_duplicates(vms: list[dict], resources: list[dict]):
    """(machines to analyze, duplicate instance rows, Flexible instances without a VM) from the inventory rows."""
    flexible = {r['id'].lower() for r in resources
                if str(r.get('type', '')).lower() == VMSS_TYPE and str((r.get('properties') or {}).get('orchestrationMode', '')).lower() == 'flexible'}
    if not flexible:
        return vms, [], []
    members, names = set(), set()
    for r in resources:
        if str(r.get('type', '')).lower() != VM_TYPE:
            continue
        parent = (((r.get('properties') or {}).get('virtualMachineScaleSet') or {}).get('id') or '').lower()
        members.add((parent, str(r.get('name', '')).lower()))
        names.add((str(r.get('subscriptionId', '')).lower(), str(r.get('name', '')).lower()))
    kept, duplicates, missing = [], [], []
    for v in vms:
        parent = str(v.get('metricResourceId') or '').lower()
        if v.get('kind') != 'vmss' or parent not in flexible:
            kept.append(v)
        elif (parent, str(v.get('name', '')).lower()) in members or (str(v.get('subscriptionId', '')).lower(), str(v.get('name', '')).lower()) in names:
            duplicates.append(v)
        else:
            missing.append(v)
    return kept, duplicates, missing


def note(duplicates: int, missing: int) -> str:
    """Sentence for the report scope; empty when nothing was removed."""
    if not duplicates and not missing:
        return ''
    parts = []
    if duplicates:
        parts.append(f'Flexible 编排的虚拟机规模集里的机器同时是独立虚拟机，已按虚拟机计一次（去掉 {duplicates} 条重复记录）')
    if missing:
        parts.append(f'另有 {missing} 个实例在采集时已不存在或无法读取（多为自动伸缩已删除的机器），未计入')
    return '；'.join(parts) + '。'


def mark_appliances(vms: list[dict], resources: list[dict], names=None) -> int:
    """Set v['appliance'] (why it is a network appliance) from the VM or its scale set in the inventory; returns how many."""
    from ..core import appliance
    known = appliance.index([r for r in resources if str(r.get('type', '')).lower() in (VM_TYPE, VMSS_TYPE)], names)
    count = 0
    for v in vms:
        reason = known.get(str(v['id'] if v.get('kind') == 'vm' else v.get('metricResourceId') or v['id']).lower())
        if reason:
            v['appliance'] = reason
            count += 1
    return count
