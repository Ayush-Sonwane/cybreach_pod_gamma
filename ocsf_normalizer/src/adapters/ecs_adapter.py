import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger("ocsf_normalizer")

class EcsAdapter:
    """
    Adapter to normalize Elastic Security logs (ECS schema) 
    into the standard OCSF format (v1.1.0).
    """

    @staticmethod
    def _to_epoch_ms(timestamp_str: Optional[str]) -> int:
        """Converts ISO 8601 string to Unix Epoch Milliseconds."""
        if not timestamp_str:
            return 0
        try:
            ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            return int(dt.timestamp() * 1000)
        except Exception as e:
            logger.warning(f"Failed to parse ECS timestamp '{timestamp_str}': {e}")
            return 0

    def transform_network_session(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms ECS Network Session -> OCSF Network Activity (Class UID: 4001)
        """
        source = raw_event.get("source", {})
        destination = raw_event.get("destination", {})
        event = raw_event.get("event", {})
        observer = raw_event.get("observer", {})
        network = raw_event.get("network", {})

        outcome = event.get("outcome", "unknown")
        status_id = 1 if outcome == "success" else (2 if outcome == "failure" else 99)

        return {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": self._to_epoch_ms(raw_event.get("@timestamp")),
            "status": outcome.capitalize(),
            "status_id": status_id,
            "src_endpoint": {
                "ip": source.get("ip"),
                "port": int(source["port"]) if source.get("port") is not None else None
            },
            "dst_endpoint": {
                "ip": destination.get("ip"),
                "port": int(destination["port"]) if destination.get("port") is not None else None
            },
            "connection_info": {
                "protocol_name": str(network.get("transport", "UNKNOWN")).upper()
            },
            "metadata": {
                "product": {
                    "vendor_name": observer.get("vendor", "Elastic"),
                    "name": observer.get("product", "Elasticsearch")
                },
                "version": "1.1.0"
            }
        }

    def transform_authentication(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms ECS Authentication -> OCSF Authentication (Class UID: 3002)
        """
        user = raw_event.get("user", {})
        source = raw_event.get("source", {})
        event = raw_event.get("event", {})
        observer = raw_event.get("observer", {})

        outcome = event.get("outcome", "unknown")
        status_id = 1 if outcome == "success" else (2 if outcome == "failure" else 99)

        return {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "Identity & Access Management",
            "time": self._to_epoch_ms(raw_event.get("@timestamp")),
            "status": outcome.capitalize(),
            "status_id": status_id,
            "status_detail": event.get("reason"),
            "user": {
                "name": user.get("name"),
                "uid": str(user.get("id")) if user.get("id") is not None else None
            },
            "src_endpoint": {
                "ip": source.get("ip")
            },
            "metadata": {
                "product": {
                    "vendor_name": observer.get("vendor", "Elastic"),
                    "name": observer.get("product", "Elasticsearch")
                },
                "version": "1.1.0"
            }
        }