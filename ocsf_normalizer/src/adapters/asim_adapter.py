import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("ocsf_normalizer")

class AsimAdapter:
    """
    Adapter to normalize Microsoft Sentinel logs (ASIM schema) 
    into the standard OCSF format (v1.1.0).
    """

    @staticmethod
    def _to_epoch_ms(timestamp_str: Optional[str]) -> int:
        """Converts ISO 8601 string to Unix Epoch Milliseconds."""
        if not timestamp_str:
            return 0
        try:
            # Handle ISO string Z offset format
            ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            return int(dt.timestamp() * 1000)
        except Exception as e:
            logger.warning(f"Failed to parse ASIM timestamp '{timestamp_str}': {e}")
            return 0

    def transform_network_session(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms ASIM NetworkSession -> OCSF Network Activity (Class UID: 4001)
        """
        event_result = raw_event.get("EventResult", "Unknown")
        status_id = 1 if event_result == "Success" else (2 if event_result == "Failure" else 99)

        return {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": self._to_epoch_ms(raw_event.get("TimeGenerated") or raw_event.get("EventStartTime")),
            "status": event_result,
            "status_id": status_id,
            "src_endpoint": {
                "ip": raw_event.get("SrcIpAddr"),
                "port": int(raw_event["SrcPortNumber"]) if raw_event.get("SrcPortNumber") is not None else None
            },
            "dst_endpoint": {
                "ip": raw_event.get("DstIpAddr"),
                "port": int(raw_event["DstPortNumber"]) if raw_event.get("DstPortNumber") is not None else None
            },
            "connection_info": {
                "protocol_name": raw_event.get("NetworkProtocol", "UNKNOWN").upper()
            },
            "metadata": {
                "product": {
                    "vendor_name": raw_event.get("EventVendor", "Microsoft"),
                    "name": raw_event.get("EventProduct", "Sentinel")
                },
                "version": "1.1.0"
            }
        }

    def transform_authentication(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms ASIM Authentication -> OCSF Authentication (Class UID: 3002)
        """
        event_result = raw_event.get("EventResult", "Unknown")
        status_id = 1 if event_result == "Success" else (2 if event_result == "Failure" else 99)

        return {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "Identity & Access Management",
            "time": self._to_epoch_ms(raw_event.get("EventStartTime") or raw_event.get("TimeGenerated")),
            "status": event_result,
            "status_id": status_id,
            "status_detail": raw_event.get("EventResultDetails"),
            "user": {
                "name": raw_event.get("TargetUsername"),
                "email_addr": raw_event.get("TargetUserUpn")
            },
            "src_endpoint": {
                "ip": raw_event.get("SrcIpAddr")
            },
            "metadata": {
                "product": {
                    "vendor_name": raw_event.get("EventVendor", "Microsoft"),
                    "name": raw_event.get("EventProduct", "Sentinel")
                },
                "version": "1.1.0"
            }
        }