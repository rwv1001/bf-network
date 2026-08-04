"""
Shared HP5130 policy JSON generator.

The generated file is consumed by /scripts/hp5130-acl-baseline.sh so the
switch baseline is derived from the same database state as the admin UI:
configured ISP routers, per-VLAN ISP assignments, subnet prefixes and visible
VLAN isolation settings.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from models import ISPRouter, Setting, VlanMapping


DEFAULT_POLICY_PATH = "/scripts/scriptdata/hp5130-policy.json"


def _network_word() -> str:
    return os.getenv("NETWORK_WORD", "192.168").strip() or "192.168"


def _policy_path() -> Path:
    return Path(os.getenv("HP5130_POLICY_PATH", DEFAULT_POLICY_PATH))


def _safe_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _vlan_prefix(mapping: VlanMapping) -> int:
    raw = Setting.get_value(f"vlan_prefix_{mapping.status}", "24")
    prefix = _safe_int(raw, 24) or 24
    if prefix < 8 or prefix > 30:
        return 24
    return prefix


def _parse_visible_vlans(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, str):
        parts: Iterable[Any] = value.split(",")
    else:
        parts = value

    seen: set[int] = set()
    result: list[int] = []
    for part in parts:
        vlan_id = _safe_int(str(part).strip(), None)
        if vlan_id is None or vlan_id in seen:
            continue
        seen.add(vlan_id)
        result.append(vlan_id)
    return result


def _default_router_id(routers: list[ISPRouter]) -> int | None:
    if not routers:
        return None

    default_name = os.getenv("DEFAULT_ISP_ROUTER_NAME", "UDM").strip().lower()
    if default_name:
        for router in routers:
            if (router.name or "").strip().lower() == default_name:
                return router.id

    default_vlan = _safe_int(os.getenv("DEFAULT_ISP_ROUTER_VLAN", "1"), 1)
    for router in routers:
        if router.vlan_id == default_vlan:
            return router.id

    return routers[0].id


def _router_record(router: ISPRouter) -> dict[str, Any]:
    return {
        "id": router.id,
        "name": router.name,
        "subnet": router.subnet,
        "vlan_id": router.vlan_id,
        "gateway_ip": router.gateway_ip,
        "switch_port": router.switch_port,
        "switch_host": router.switch_host,
        "dhcp_snooping_trust": bool(router.dhcp_snooping_trust),
        "nat_logger_type": router.nat_logger_type,
        "pbr_name": router.pbr_name,
        # Existing switch code uses router.id as the NQA/track id. Export it
        # explicitly so the ACL baseline script does not have to infer it.
        "track_id": router.id,
        # Reserve uplink ACLs by router VLAN, not database id, so changing or
        # recreating rows cannot make the script overwrite another router ACL.
        "uplink_acl": 3950 + int(router.vlan_id),
    }


def _vlan_record(mapping: VlanMapping, router_ids: set[int], default_router_id: int | None) -> dict[str, Any]:
    network_word = _network_word()
    prefix = _vlan_prefix(mapping)
    vlan_id = int(mapping.vlan_id)
    subnet = ipaddress.IPv4Network(f"{network_word}.{vlan_id}.0/{prefix}", strict=False)

    configured_router_id = mapping.isp_router_id if mapping.isp_router_id in router_ids else None
    resolved_router_id = configured_router_id if configured_router_id is not None else default_router_id

    return {
        "status": mapping.status,
        "name": mapping.display_name or mapping.status.title(),
        "vlan_id": vlan_id,
        "ssid": mapping.ssid,
        "wired_enabled": bool(mapping.wired_enabled),
        "require_password": bool(mapping.require_password),
        "prefix": prefix,
        "subnet": str(subnet),
        "network_address": str(subnet.network_address),
        "netmask": str(subnet.netmask),
        "hostmask": str(subnet.hostmask),
        "isp_router_id": configured_router_id,
        "resolved_isp_router_id": resolved_router_id,
        "visible_vlans": _parse_visible_vlans(mapping.visible_vlans),
        "isolation_acl": 3000 + vlan_id * 10 + 1,
    }


def build_hp5130_policy() -> dict[str, Any]:
    """Build the HP5130 policy document from the current database state."""
    routers = ISPRouter.query.order_by(ISPRouter.id).all()
    router_ids = {router.id for router in routers}
    default_router_id = _default_router_id(routers)

    mappings = (
        VlanMapping.query
        .filter(VlanMapping.vlan_id.isnot(None))
        .order_by(VlanMapping.vlan_id)
        .all()
    )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_word": _network_word(),
        "local_network": f"{_network_word()}.0.0/16",
        "policy_path": str(_policy_path()),
        "default_router_id": default_router_id,
        "routers": [_router_record(router) for router in routers],
        "vlans": [
            _vlan_record(mapping, router_ids, default_router_id)
            for mapping in mappings
        ],
    }


def write_hp5130_policy_file(path: str | os.PathLike[str] | None = None) -> str:
    """
    Atomically write the HP5130 policy JSON and return the path written.

    The default path is /scripts/scriptdata/hp5130-policy.json, overridable with
    HP5130_POLICY_PATH. The parent directory is created if needed.
    """
    target = Path(path) if path is not None else _policy_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    data = build_hp5130_policy()
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    return str(target)
