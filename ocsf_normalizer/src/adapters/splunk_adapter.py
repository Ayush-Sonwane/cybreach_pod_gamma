import time
from typing import Dict, Any

# Import models directly from models.py
from models import (
    OCSFAuthenticationModel,
    UserModel,
    DeviceModel,
    ActorModel
)

class SplunkOCSFAdapter:
    """
    Adapter to detect Splunk CIM payloads and convert them into your exact OCSF Authentication Model.
    """

    @staticmethod
    def is_splunk_payload(payload: Dict[str, Any]) -> bool:
        """
        Schema Detection Logic: Identifies whether an incoming payload is a Splunk event/CIM format.
        """
        splunk_indicators = ["sourcetype", "eventtype", "_raw", "_time"]
        cim_auth_indicators = ["action", "user", "src", "dest"]

        has_splunk_keys = any(key in payload for key in splunk_indicators)
        has_cim_keys = any(key in payload for key in cim_auth_indicators)

        return has_splunk_keys or has_cim_keys

    @classmethod
    def map_to_ocsf(cls, payload: Dict[str, Any]) -> OCSFAuthenticationModel:
        """
        Maps Splunk CIM fields directly into your OCSFAuthenticationModel schema.
        """
        # 1. Map Action -> Status ID (1 = Success, 2 = Failure, 99 = Unknown in standard OCSF)
        raw_action = str(payload.get("action", "")).lower()
        if raw_action in ["success", "successful", "succeeded"]:
            status_id = 1
        elif raw_action in ["failure", "failed", "error"]:
            status_id = 2
        else:
            status_id = 99

        # 2. Extract User details
        username = payload.get("user") or payload.get("src_user") or "Unknown"
        user_obj = UserModel(name=username)

        # 3. Extract Device/Endpoint details
        src_ip = payload.get("src_ip") or payload.get("src") or "0.0.0.0"
        device_obj = DeviceModel(ip=src_ip)

        # 4. Extract Actor (In auth logs, actor is usually the same user or system process)
        actor_user = payload.get("src_user") or username
        actor_obj = ActorModel(user=UserModel(name=actor_user))

        # 5. Construct Normalized OCSF Object strictly matching your models.py
        return OCSFAuthenticationModel(
            activity_id=1,        # 1 = Logon in OCSF Authentication
            category_uid=3,       # 3 = Identity & Access Management
            class_uid=3002,       # 3002 = Authentication
            severity_id=1,       # 1 = Informational / Low
            status_id=status_id,
            user=user_obj,
            device=device_obj,
            actor=actor_obj
        )