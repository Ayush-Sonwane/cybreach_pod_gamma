"""
Canonical OCSF Event Models (OCSF v1.2+)

- ``OCSFEvent``: Generic OCSF event with the full set of complex objects
  (endpoint, file, process, user, device, actor).
- ``OCSFAuthenticationEvent``: OCSF Authentication event (Class 3001/3002,
  Category 3) built on top of the same typed complex objects.

Both models preserve the ``provenance`` field for field-level auditability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.models.ocsf_objects import (
    Actor,
    Device,
    Endpoint,
    FieldProvenance,
    File,
    Process,
    User,
)


class OCSFEvent(BaseModel):
    """
    Generic OCSF Event.

    Supports the full range of complex OCSF objects so it can represent
    any event class (Authentication, Network Activity, File Activity, etc.).
    """

    model_config = ConfigDict(populate_by_name=True)

    # Core mandatory OCSF fields
    class_uid: int = Field(..., description="OCSF Event Class UID")
    category_uid: int = Field(..., description="OCSF Event Category UID")
    activity_id: int = Field(default=0, description="OCSF Activity ID")
    severity_id: int = Field(default=1, description="OCSF Severity ID (1-6)")
    status_id: int = Field(default=99, description="OCSF Status ID")
    time: int = Field(..., description="Epoch timestamp in milliseconds")

    # Optional base metadata
    message: Optional[str] = None
    type_uid: Optional[int] = None
    type_name: Optional[str] = None

    # Complex OCSF objects
    user: Optional[User] = None
    actor: Optional[Actor] = None
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    file: Optional[File] = None
    process: Optional[Process] = None
    device: Optional[Device] = None

    # Provenance / auditability
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, FieldProvenance] = Field(default_factory=dict)


class OCSFAuthenticationEvent(OCSFEvent):
    """
    Canonical OCSF v1.2+ Authentication Event (Class 3001/3002, Category 3).

    Inherits the full set of typed complex objects from :class:`OCSFEvent`
    and adds authentication-specific default class/category UIDs.
    """

    class_uid: int = Field(default=3001, description="Authentication Class")
    category_uid: int = Field(default=3, description="Identity & Access Management")
    activity_id: int = Field(default=1, description="1: Log In, 2: Log Out, 99: Other")
    severity_id: int = Field(default=1, description="1: Informational .. 5: Critical")
    time: int = Field(..., description="Epoch timestamp in milliseconds")
    status_id: int = Field(default=99, description="1: Success, 2: Failure, 99: Unknown")


OCSFAuthenticationModel = OCSFAuthenticationEvent

