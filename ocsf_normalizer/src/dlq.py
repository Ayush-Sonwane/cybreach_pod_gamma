import time
from typing import Dict, Any, List

class DeadLetterQueue:
    """
    Handles buffering and formatting of unparseable or schema-invalid logs.
    In production, this flushes events to an error storage bucket, file, or Kafka topic.
    """

    def __init__(self):
        self.queue: List[Dict[str, Any]] = []

    def push(self, raw_payload: Dict[str, Any], reason: str, errors: List[str] = None) -> Dict[str, Any]:
        """
        Wraps the bad log with diagnostic metadata and queues it.
        """
        dlq_record = {
            "dlq_timestamp": int(time.time() * 1000),
            "failure_reason": reason,
            "validation_errors": errors or [],
            "raw_payload": raw_payload
        }
        self.queue.append(dlq_record)
        return dlq_record

    def get_queue(self) -> List[Dict[str, Any]]:
        return self.queue

    def clear(self):
        self.queue.clear()