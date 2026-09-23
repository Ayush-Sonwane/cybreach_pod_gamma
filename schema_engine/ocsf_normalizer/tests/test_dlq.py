"""
Dead Letter Queue tests: buffering unparseable/schema-invalid logs (Pod Gamma, Module 2).
"""
from src.dlq import DeadLetterQueue


def test_push_records_diagnostic_metadata():
    dlq = DeadLetterQueue()
    record = dlq.push({"raw": "payload"}, reason="unknown schema", errors=["no match"])
    assert record["failure_reason"] == "unknown schema"
    assert record["validation_errors"] == ["no match"]
    assert isinstance(record["dlq_timestamp"], int)
    assert record["raw_payload"] == {"raw": "payload"}


def test_push_queues_event_and_get_queue_returns_it():
    dlq = DeadLetterQueue()
    dlq.push({"a": 1}, reason="bad")
    queue = dlq.get_queue()
    assert len(queue) == 1
    assert queue[0]["raw_payload"] == {"a": 1}


def test_push_defaults_errors_to_empty_list():
    dlq = DeadLetterQueue()
    record = dlq.push({"a": 1}, reason="bad")
    assert record["validation_errors"] == []


def test_clear_empties_queue():
    dlq = DeadLetterQueue()
    dlq.push({"a": 1}, reason="bad")
    dlq.clear()
    assert dlq.get_queue() == []


def test_multiple_pushes_preserve_order():
    dlq = DeadLetterQueue()
    dlq.push({"a": 1}, reason="first")
    dlq.push({"b": 2}, reason="second")
    reasons = [r["failure_reason"] for r in dlq.get_queue()]
    assert reasons == ["first", "second"]
