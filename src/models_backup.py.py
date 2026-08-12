from pydantic import BaseModel, Field
from typing import Optional

class UserModel(BaseModel):
    name: str
    uid: Optional[str] = None
    domain: Optional[str] = None

class DeviceModel(BaseModel):
    ip: str
    port: Optional[int] = None  # Handled as an integer for port numbers

class ActorModel(BaseModel):
    user: UserModel

# The Master Model that matches our windows_auth.json structure
class OCSFAuthenticationModel(BaseModel):
    activity_id: int
    category_uid: int
    class_uid: int
    severity_id: int
    status_id: int
    user: UserModel
    device: DeviceModel
    actor: ActorModel
class RevalidateRequest(BaseModel):
    event_id: str = Field(..., min_length=1)
    original_event: Dict[str, Any]
    event: Dict[str, Any]


class RevalidateResponse(BaseModel):
    re_run_id: str
    event_id: str
    status: str
    valid: bool
    errors: List[str] = Field(default_factory=list)
    idempotent: bool = False


class DeltaChange(BaseModel):
    field: str
    before: Optional[Any] = None
    after: Optional[Any] = None


class DeltaResponse(BaseModel):
    re_run_id: str
    event_id: str
    changes: List[DeltaChange] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    code: str
    message: str
