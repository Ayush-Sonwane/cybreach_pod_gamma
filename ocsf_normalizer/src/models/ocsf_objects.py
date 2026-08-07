from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class FieldProvenance(BaseModel):
    """Tracks raw field source for complete auditability."""

    model_config = ConfigDict(populate_by_name=True)

    original_field: str
    original_value: Any


class Hashes(BaseModel):
    """File / artifact hashes."""

    model_config = ConfigDict(populate_by_name=True)

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None


class OS(BaseModel):
    """Operating System descriptor."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    version: Optional[str] = None
    type_id: Optional[int] = None


class Group(BaseModel):
    """User group membership."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    uid: Optional[str] = None


class User(BaseModel):
    """OCSF User object."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    uid: Optional[str] = None
    domain: Optional[str] = None
    type_id: Optional[int] = None
    email_addr: Optional[str] = None
    org: Optional[str] = None
    groups: List[Group] = Field(default_factory=list)


class Endpoint(BaseModel):
    """OCSF Endpoint object (used for src_endpoint / dst_endpoint)."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    uid: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    mac: Optional[str] = None
    interface_uid: Optional[str] = None
    svc_name: Optional[str] = None
    type_id: Optional[int] = None
    os: Optional[OS] = None


class File(BaseModel):
    """OCSF File object."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    uid: Optional[str] = None
    type_id: Optional[int] = None
    hashes: Optional[Hashes] = None
    parent_folder: Optional[str] = None
    owner_user: Optional[User] = None


class Process(BaseModel):
    """OCSF Process object."""

    model_config = ConfigDict(populate_by_name=True)

    pid: Optional[int] = None
    name: Optional[str] = None
    path: Optional[str] = None
    cmd_line: Optional[str] = None
    created_time: Optional[int] = None
    user: Optional[User] = None
    file: Optional[File] = None
    parent_process: Optional[Process] = None


class Device(BaseModel):
    """OCSF Device object."""

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    uid: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    mac: Optional[str] = None
    type_id: Optional[int] = None
    os: Optional[OS] = None


class Actor(BaseModel):
    """OCSF Actor object (initiator of the event)."""

    model_config = ConfigDict(populate_by_name=True)

    user: Optional[User] = None
    process: Optional[Process] = None
    session_uid: Optional[str] = None
    type_id: Optional[int] = None

