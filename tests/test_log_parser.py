from datetime import datetime
from k8s_agent.models.log_entry import LogLevel
from k8s_agent.parser.log_parser import LogParser


def test_parse_standard_k8s_log():
    parser = LogParser()
    text = (
        "2026-10-29T10:00:00.123456789Z [my-pod/my-container] INFO App started\n"
        "2026-10-29T10:00:05.000Z [my-pod/my-container] ERROR Database connection failed\n"
    )
    entries = parser.parse(text)
    assert len(entries) == 2

    assert entries[0].line_number == 1
    assert entries[0].pod == "my-pod"
    assert entries[0].container == "my-container"
    assert entries[0].level == LogLevel.INFO
    assert entries[0].timestamp is not None
    assert entries[0].timestamp.year == 2026

    assert entries[1].line_number == 2
    assert entries[1].level == LogLevel.ERROR


def test_parse_json_logs():
    parser = LogParser()
    text = (
        '{"time":"2026-10-29T12:00:00Z","level":"error","msg":"connection reset","pod":"api-1"}\n'
        '{"timestamp":1730200000,"severity":"INFO","message":"ready"}\n'
    )
    entries = parser.parse(text)
    assert len(entries) == 2
    assert entries[0].level == LogLevel.ERROR
    assert "connection reset" in entries[0].message
    assert entries[0].pod == "api-1"
    assert entries[1].level == LogLevel.INFO


def test_multiline_stack_trace_stitching():
    parser = LogParser()
    text = (
        "2026-10-29T12:00:00Z ERROR Traceback (most recent call last):\n"
        '  File "app.py", line 12, in <module>\n'
        '    connect_db()\n'
        "psycopg2.OperationalError: could not connect\n"
        "2026-10-29T12:00:01Z INFO Continuing...\n"
    )
    entries = parser.parse(text)
    assert len(entries) == 2
    assert entries[0].is_stack_trace is True
    assert "File \"app.py\"" in entries[0].stack_trace
    assert entries[1].message == "Continuing..."
