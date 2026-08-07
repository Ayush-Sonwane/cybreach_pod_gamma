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