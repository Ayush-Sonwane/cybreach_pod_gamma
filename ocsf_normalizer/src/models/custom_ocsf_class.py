from typing import Any, Dict

from pydantic import BaseModel, Field


class CustomOCSFClassRegistration(BaseModel):
    """
    Request model for registering an organization's
    custom OCSF class/schema.
    """

    organization: str = Field(
        ...,
        min_length=1,
        description="Organization that owns the custom OCSF class",
    )

    class_name: str = Field(
        ...,
        min_length=1,
        description="Name of the custom OCSF class",
    )

    class_uid: int = Field(
        ...,
        description="Unique UID assigned to the custom OCSF class",
    )

    category_uid: int = Field(
        ...,
        description="OCSF category UID",
    )

    version: str = Field(
        ...,
        min_length=1,
        description="Version of the custom schema",
    )

    schema: Dict[str, Any] = Field(
        ...,
        description="Custom telemetry JSON schema",
    )


class CustomOCSFClassResponse(BaseModel):
    """
    Response returned after registering a custom OCSF class.
    """

    id: str
    organization: str
    class_name: str
    class_uid: int
    category_uid: int
    version: str
    schema: Dict[str, Any]
    status: str