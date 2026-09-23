# src/models/ocsf_models.py
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class FieldProvenance(BaseModel):
    """Tracks raw field source for complete auditability."""
    original_field: str
    original_value: Any

class OCSFAuthenticationEvent(BaseModel):
    """Canonical OCSF v1.2+ Authentication Event (Class 3001, Category 3)"""
    model_config = ConfigDict(populate_by_name=True)

    class_uid: int = Field(default=3001, description="Authentication Class")
    category_uid: int = Field(default=3, description="Identity & Access Management")
    activity_id: int = Field(..., description="1: Log In, 2: Log Out, 99: Other")
    severity_id: int = Field(..., description="1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical")
    time: int = Field(..., description="Epoch timestamp in milliseconds")
    status_id: int = Field(..., description="1: Success, 2: Failure, 99: Unknown")
    
    # Normalized Objects
    user: Dict[str, Any] = Field(default_factory=dict)
    src_endpoint: Dict[str, Any] = Field(default_factory=dict)
    dst_endpoint: Dict[str, Any] = Field(default_factory=dict)
    
    # Provenance Tracking
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, FieldProvenance] = Field(default_factory=dict)