from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Union

from src.models.ocsf_objects import (
    Actor,
    Device,
    Endpoint,
    FieldProvenance,
    File,
    Group,
    Hashes,
    OS,
    Process,
    User,
)

# A key map value can be a single vendor key, a list of fallback keys,
# or a callable that extracts the value from the raw payload.
KeyMapValue = Union[str, List[str], Callable[[Dict[str, Any]], Any]]


def _extract(raw: Dict[str, Any], spec: Optional[KeyMapValue]) -> Any:
    """Extract a value from ``raw`` following the key-map spec."""
    if spec is None:
        return None
    if callable(spec):
        try:
            return spec(raw)
        except (KeyError, TypeError, ValueError):
            return None

    keys = [spec] if isinstance(spec, str) else list(spec)
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def _record(
    provenance: Dict[str, FieldProvenance],
    ocsf_attr: str,
    raw: Dict[str, Any],
    spec: Optional[KeyMapValue],
) -> Any:
    """Extract + record provenance for a mapped field."""
    value = _extract(raw, spec)
    if value is not None:
        source_key = ocsf_attr
        if isinstance(spec, str):
            source_key = spec
        elif isinstance(spec, list):
            for k in spec:
                if k in raw and raw[k] is not None:
                    source_key = k
                    break
        provenance[f"mapped.{ocsf_attr}"] = FieldProvenance(
            original_field=source_key, original_value=value
        )
    return value


def _int(value: Any) -> Optional[int]:
    """Best-effort integer coercion."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _bool_int(value: Any) -> Optional[int]:
    """Coerce a boolean-ish value to 0/1."""
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    return _int(value)


def build_user(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[User]:
    """Build an OCSF User object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "name": ["user_name", "username", "user"],
        "uid": ["user_uid", "user_sid", "user_id"],
        "domain": ["user_domain", "domain"],
        "email_addr": ["user_email", "email_addr"],
        "type_id": "user_type_id",
    }
    merged = {**defaults, **key_map}

    name = _record(provenance, "user.name", raw, merged.get("name", "user"))
    uid = _record(provenance, "user.uid", raw, merged.get("uid"))
    domain = _record(provenance, "user.domain", raw, merged.get("domain"))
    email = _record(provenance, "user.email_addr", raw, merged.get("email_addr"))
    type_id = _int(_record(provenance, "user.type_id", raw, merged.get("type_id")))

    if name is None and uid is None and domain is None:
        return None

    groups = []
    group_names = _record(provenance, "user.groups", raw, merged.get("groups"))
    if isinstance(group_names, (list, tuple)):
        for g in group_names:
            if isinstance(g, str):
                groups.append(Group(name=g))
            elif isinstance(g, dict):
                groups.append(Group(**{k: v for k, v in g.items() if v is not None}))

    return User(
        name=name,
        uid=uid,
        domain=domain,
        email_addr=email,
        type_id=type_id,
        groups=groups,
    )


def build_endpoint(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[Endpoint]:
    """Build an OCSF Endpoint object (src_endpoint / dst_endpoint)."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "ip": "ip",
        "port": "port",
        "hostname": "hostname",
        "name": "name",
        "domain": "domain",
        "mac": "mac",
        "uid": "uid",
        "svc_name": "svc_name",
        "interface_uid": "interface_uid",
        "type_id": "type_id",
    }
    merged = {**defaults, **key_map}

    ip = _record(provenance, "endpoint.ip", raw, merged.get("ip"))
    port = _int(_record(provenance, "endpoint.port", raw, merged.get("port")))
    hostname = _record(provenance, "endpoint.hostname", raw, merged.get("hostname"))
    name = _record(provenance, "endpoint.name", raw, merged.get("name"))
    domain = _record(provenance, "endpoint.domain", raw, merged.get("domain"))
    mac = _record(provenance, "endpoint.mac", raw, merged.get("mac"))
    uid = _record(provenance, "endpoint.uid", raw, merged.get("uid"))
    svc_name = _record(provenance, "endpoint.svc_name", raw, merged.get("svc_name"))
    interface_uid = _record(
        provenance, "endpoint.interface_uid", raw, merged.get("interface_uid")
    )
    type_id = _int(_record(provenance, "endpoint.type_id", raw, merged.get("type_id")))

    os_raw = _record(provenance, "endpoint.os", raw, merged.get("os"))
    os_obj = None
    if isinstance(os_raw, dict):
        os_obj = OS(name=os_raw.get("name"), version=os_raw.get("version"))

    if ip is None and port is None and hostname is None and name is None:
        return None

    return Endpoint(
        ip=ip,
        port=port,
        hostname=hostname,
        name=name,
        domain=domain,
        mac=mac,
        uid=uid,
        svc_name=svc_name,
        interface_uid=interface_uid,
        type_id=type_id,
        os=os_obj,
    )


def build_hashes(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[Hashes]:
    """Build an OCSF Hashes object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "md5": "file_hash_md5",
        "sha1": "file_hash_sha1",
        "sha256": "file_hash_sha256",
        "sha512": "file_hash_sha512",
    }
    merged = {**defaults, **key_map}

    md5 = _record(provenance, "file.hashes.md5", raw, merged.get("md5"))
    sha1 = _record(provenance, "file.hashes.sha1", raw, merged.get("sha1"))
    sha256 = _record(provenance, "file.hashes.sha256", raw, merged.get("sha256"))
    sha512 = _record(provenance, "file.hashes.sha512", raw, merged.get("sha512"))

    if not any([md5, sha1, sha256, sha512]):
        return None
    return Hashes(md5=md5, sha1=sha1, sha256=sha256, sha512=sha512)


def build_file(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[File]:
    """Build an OCSF File object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "name": "file_name",
        "path": "file_path",
        "size": "file_size",
        "uid": "file_uid",
        "type_id": "file_type_id",
        "parent_folder": "file_parent_folder",
        "hashes": "file_hashes",
        "owner_user": "file_owner",
    }
    merged = {**defaults, **key_map}

    name = _record(provenance, "file.name", raw, merged.get("name"))
    path = _record(provenance, "file.path", raw, merged.get("path"))
    size = _int(_record(provenance, "file.size", raw, merged.get("size")))
    uid = _record(provenance, "file.uid", raw, merged.get("uid"))
    type_id = _int(_record(provenance, "file.type_id", raw, merged.get("type_id")))
    parent_folder = _record(
        provenance, "file.parent_folder", raw, merged.get("parent_folder")
    )

    hashes = None
    hashes_spec = merged.get("hashes")
    if isinstance(hashes_spec, dict):
        # key_map may already include explicit hash mappings -> build Hashes
        hashes = build_hashes(raw, hashes_spec, provenance)
    else:
        hash_val = _extract(raw, hashes_spec) if hashes_spec else None
        if isinstance(hash_val, dict):
            hashes = Hashes(
                md5=hash_val.get("md5"),
                sha1=hash_val.get("sha1"),
                sha256=hash_val.get("sha256"),
                sha512=hash_val.get("sha512"),
            )

    if name is None and path is None and uid is None:
        return None

    return File(
        name=name,
        path=path,
        size=size,
        uid=uid,
        type_id=type_id,
        parent_folder=parent_folder,
        hashes=hashes,
    )


def build_process(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[Process]:
    """Build an OCSF Process object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "pid": "pid",
        "name": "process_name",
        "path": "process_path",
        "cmd_line": "process_cmd_line",
        "created_time": "process_created_time",
        "user": "process_user",
        "file": "process_file",
    }
    merged = {**defaults, **key_map}

    pid = _int(_record(provenance, "process.pid", raw, merged.get("pid")))
    name = _record(provenance, "process.name", raw, merged.get("name"))
    path = _record(provenance, "process.path", raw, merged.get("path"))
    cmd_line = _record(provenance, "process.cmd_line", raw, merged.get("cmd_line"))
    created_time = _int(
        _record(provenance, "process.created_time", raw, merged.get("created_time"))
    )

    user = None
    user_spec = merged.get("user")
    if isinstance(user_spec, dict):
        user = build_user(raw, user_spec, provenance)
    elif isinstance(user_spec, str) and user_spec:
        username = _record(provenance, "process.user.name", raw, user_spec)
        if username is not None:
            user = User(name=username)

    if pid is None and name is None and path is None and cmd_line is None:
        return None

    return Process(
        pid=pid,
        name=name,
        path=path,
        cmd_line=cmd_line,
        created_time=created_time,
        user=user,
    )


def build_device(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[Device]:
    """Build an OCSF Device object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "name": "device_name",
        "uid": "device_uid",
        "ip": "device_ip",
        "port": "device_port",
        "hostname": "device_hostname",
        "domain": "device_domain",
        "mac": "device_mac",
        "type_id": "device_type_id",
        "os": "device_os",
    }
    merged = {**defaults, **key_map}

    name = _record(provenance, "device.name", raw, merged.get("name"))
    uid = _record(provenance, "device.uid", raw, merged.get("uid"))
    ip = _record(provenance, "device.ip", raw, merged.get("ip"))
    port = _int(_record(provenance, "device.port", raw, merged.get("port")))
    hostname = _record(provenance, "device.hostname", raw, merged.get("hostname"))
    domain = _record(provenance, "device.domain", raw, merged.get("domain"))
    mac = _record(provenance, "device.mac", raw, merged.get("mac"))
    type_id = _int(_record(provenance, "device.type_id", raw, merged.get("type_id")))

    os_raw = _record(provenance, "device.os", raw, merged.get("os"))
    os_obj = None
    if isinstance(os_raw, dict):
        os_obj = OS(name=os_raw.get("name"), version=os_raw.get("version"))

    if name is None and ip is None and hostname is None and uid is None:
        return None

    return Device(
        name=name,
        uid=uid,
        ip=ip,
        port=port,
        hostname=hostname,
        domain=domain,
        mac=mac,
        type_id=type_id,
        os=os_obj,
    )


def build_actor(
    raw: Dict[str, Any],
    key_map: Dict[str, KeyMapValue],
    provenance: Optional[Dict[str, FieldProvenance]] = None,
) -> Optional[Actor]:
    """Build an OCSF Actor object from vendor fields."""
    provenance = provenance if provenance is not None else {}
    defaults: Dict[str, KeyMapValue] = {
        "user": "actor_user",
        "process": "actor_process",
        "session_uid": "session_uid",
        "type_id": "actor_type_id",
    }
    merged = {**defaults, **key_map}

    user = None
    user_spec = merged.get("user")
    if isinstance(user_spec, dict):
        user = build_user(raw, user_spec, provenance)
    elif isinstance(user_spec, str) and user_spec:
        username = _record(provenance, "actor.user.name", raw, user_spec)
        if username is not None:
            user = User(name=username)

    process = None
    process_spec = merged.get("process")
    if isinstance(process_spec, dict):
        process = build_process(raw, process_spec, provenance)

    session_uid = _record(provenance, "actor.session_uid", raw, merged.get("session_uid"))
    type_id = _int(_record(provenance, "actor.type_id", raw, merged.get("type_id")))

    if user is None and process is None and session_uid is None:
        return None

    return Actor(user=user, process=process, session_uid=session_uid, type_id=type_id)

