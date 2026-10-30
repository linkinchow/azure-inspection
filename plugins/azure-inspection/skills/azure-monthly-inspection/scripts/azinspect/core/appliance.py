"""Network appliances (firewalls, routers, packet brokers) running as virtual machines.

They are vendor systems, not ordinary servers: memory readings reported by the guest can be meaningless, IP forwarding
is required, administrators log in with passwords on the management port, the vendor maintains the operating system,
and only the sizes the vendor supports (often tied to vCPU licences) can be used. Checks that assume an ordinary VM
treat them apart.

Recognised only from what the platform reports, never guessed from words like "firewall" in a name:
- the image publisher or the Marketplace plan publisher is a network appliance vendor (Marketplace publisher IDs);
- the operating system reported by the VM agent is an appliance OS;
- or the customer's own name rule `rules.networkAppliances` in customer.yaml (for custom images).
"""
from __future__ import annotations

PUBLISHERS = {'fortinet', 'paloaltonetworks', 'checkpoint', 'gigamon-inc', 'cisco', 'f5-networks', 'barracudanetworks',
              'juniper-networks', 'sophos', 'netgate', 'aviatrix-systems', 'versa-networks', 'arista-networks',
              'silver-peak-systems', 'zscaler', 'imperva', 'a10networks', 'kemptech', 'radware', 'watchguard-technologies'}
OS_NAMES = ('fortios', 'pan-os', 'panos', 'gaia', 'junos', 'sophos', 'barracuda')


def _image(row):
    props = row.get('properties') or {}
    storage = props.get('storageProfile') or (props.get('virtualMachineProfile') or {}).get('storageProfile') or {}
    return storage.get('imageReference') or row.get('imageReference') or {}     # nested ARG row, or a projected column


def of(row: dict, names=None) -> str | None:
    """Why this Resource Graph VM or scale set row is a network appliance, or None. `names`: compiled customer name rule."""
    publisher = str(_image(row).get('publisher') or '').lower()
    if publisher in PUBLISHERS:
        return f'镜像发布者 {publisher}'
    plan = str((row.get('plan') or {}).get('publisher') or '').lower()
    if plan in PUBLISHERS:
        return f'购买计划发布者 {plan}'
    os_name = str((((row.get('properties') or {}).get('extended') or {}).get('instanceView') or {}).get('osName') or row.get('osName') or '')
    if os_name and any(os_name.lower().startswith(x) for x in OS_NAMES):
        return f'系统 {os_name}'
    if names is not None and names.search(str(row.get('name') or '')):
        return '名称规则（customer.yaml）'
    return None


def index(rows, names=None) -> dict:
    """{lower resource id: reason} for the appliance rows."""
    out = {}
    for r in rows:
        reason = of(r, names)
        if reason:
            out[str(r.get('id') or '').lower()] = reason
    return out
