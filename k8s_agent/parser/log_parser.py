"""Kubernetes and container log parsing with multi-line stack trace support."""

from datetime import datetime, timezone
import json
import re
from typing import List, Optional, Tuple

from k8s_agent.models.log_entry import LogEntry, LogLevel

# Regex patterns for timestamp extraction
TIMESTAMP_PATTERNS = [
    # RFC3339 / ISO8601 with fractional seconds and Z or offset: 2026-10-29T13:45:00.123456789Z
    (
        re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
        "%Y-%m-%d %H:%M:%S",  # fallback helper
    ),
    # Standard datetime with comma or dot: 2026-10-29 13:45:00,123
    (
        re.compile(r"^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3,6})"),
        None,
    ),
    # Syslog style: Oct 29 13:45:00
    (
        re.compile(r"^\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
        None,
    ),
]

# Regex for container/pod prefixes (e.g. [pod/container] or pod/container: or [pod] but not matching timestamp digits)
CONTAINER_PREFIX_REGEX = re.compile(
    r"^(?:\[(?P<pod1>[a-zA-Z0-9_\-\.]+)(?:/(?P<c1>[a-zA-Z0-9_\-\.]+))?\]|"
    r"(?P<pod2>[a-zA-Z0-9_\-\.]+)/(?P<c2>[a-zA-Z0-9_\-\.]+):)\s*"
)

# CRI-O / containerd stream tag regex: e.g. "2026-10-29T...Z stdout F ..." or "... stderr F ..."
CRI_REGEX = re.compile(r"^(?:stdout|stderr)\s+[FP]\s+", re.IGNORECASE)

# Log levels
LEVEL_REGEX = re.compile(
    r"\b(FATAL|PANIC|CRITICAL|CRIT|SEVERE|EMERGENCY|EMERG|ERROR|ERR|WARN|WARNING|WRN|INFO|INF|DEBUG|DBG|TRACE)\b",
    re.IGNORECASE,
)

# Stack trace indicators
STACK_START_REGEX = re.compile(
    r"(Traceback \(most recent call last\):|"
    r"panic: runtime error|"
    r"goroutine \d+ \[[^\]]+\]:|"
    r"^[a-zA-Z0-9_\.]+(?:Exception|Error):|"
    r"^\s*at\s+[a-zA-Z0-9_\.<>]+\(|"
    r"^\s*Caused by:\s+[a-zA-Z0-9_\.]+)",
    re.MULTILINE,
)

STACK_CONTINUATION_REGEX = re.compile(
    r"^\s+(at\s+|File\s+\"|Caused by:|\.\.\.\s+\d+\s+more|[a-zA-Z0-9_\/\-\.]+\.go:\d+|\t)",
    re.IGNORECASE,
)


class LogParser:
    """Parses raw Kubernetes log output into structured LogEntry objects."""

    def __init__(self):
        pass

    def parse(self, text: str) -> List[LogEntry]:
        """Parse raw log text string into a list of LogEntry items."""
        if not text:
            return []

        raw_lines = text.splitlines()
        entries: List[LogEntry] = []
        current_entry: Optional[LogEntry] = None

        for idx, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            # Check if this line is a continuation of a stack trace
            if current_entry and self._is_stack_continuation(line, current_entry):
                if current_entry.stack_trace:
                    current_entry.stack_trace += "\n" + line
                else:
                    current_entry.stack_trace = current_entry.raw + "\n" + line
                current_entry.is_stack_trace = True
                continue

            # Otherwise, parse as a new log line
            entry = self._parse_single_line(line, line_number=idx)
            entries.append(entry)
            current_entry = entry

        return entries

    def _is_stack_continuation(self, line: str, current_entry: Optional[LogEntry]) -> bool:
        """Determines if the given line continues a previous stack trace."""
        if STACK_CONTINUATION_REGEX.search(line):
            return True
        # Lines with significant indentation often continue an error
        if line.startswith("    ") or line.startswith("\t"):
            return True
        # In Python tracebacks, the concluding exception line has no indent
        # e.g. "psycopg2.OperationalError: could not connect"
        if current_entry and current_entry.is_stack_trace and current_entry.stack_trace:
            last_line = current_entry.stack_trace.splitlines()[-1]
            if last_line.strip().startswith("File ") or last_line.startswith("  "):
                if re.match(r"^[a-zA-Z0-9_\.]+(?:Error|Exception|Panic):", line.strip()):
                    return True
        return False

    def _parse_single_line(self, raw_line: str, line_number: int) -> LogEntry:
        """Parse a single line into a LogEntry."""
        line = raw_line.strip()
        timestamp: Optional[datetime] = None
        pod: Optional[str] = None
        container: Optional[str] = None
        level = LogLevel.UNKNOWN
        stack_trace: Optional[str] = None

        # 1. Try parsing as JSON first
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return self._parse_json_line(data, raw_line, line_number)
            except Exception:
                pass

        working_line = line

        # 2. Extract timestamp first if at line start
        ts, remaining = self._extract_timestamp(working_line)
        if ts:
            timestamp = ts
            working_line = remaining

        # 3. Extract container/pod prefix if present (either before or after timestamp)
        m_prefix = CONTAINER_PREFIX_REGEX.match(working_line)
        if m_prefix:
            pod = m_prefix.group("pod1") or m_prefix.group("pod2")
            container = m_prefix.group("c1") or m_prefix.group("c2")
            working_line = working_line[m_prefix.end():].strip()

        # If timestamp wasn't at the very start, check if it's after container prefix
        if not timestamp:
            ts, remaining = self._extract_timestamp(working_line)
            if ts:
                timestamp = ts
                working_line = remaining

        # 4. Check for CRI prefix (stdout F / stderr F)
        m_cri = CRI_REGEX.match(working_line)
        if m_cri:
            stream_type = m_cri.group(0).lower()
            if "stderr" in stream_type and level == LogLevel.UNKNOWN:
                level = LogLevel.WARN
            working_line = working_line[m_cri.end():].strip()

        # 5. Extract log level
        extracted_level, remaining_after_level = self._extract_level(working_line)
        if extracted_level != LogLevel.UNKNOWN:
            level = extracted_level
            working_line = remaining_after_level

        # 6. Check for stack trace initiation
        is_stack = bool(STACK_START_REGEX.search(line))
        if is_stack:
            stack_trace = line
            if level == LogLevel.UNKNOWN:
                level = LogLevel.ERROR

        # 7. Check if K8s event format (e.g. Warning Unhealthy, Normal Scheduled)
        if working_line.startswith("Warning "):
            level = LogLevel.WARN
        elif working_line.startswith("Normal "):
            level = LogLevel.INFO

        return LogEntry(
            line_number=line_number,
            raw=raw_line,
            message=working_line,
            timestamp=timestamp,
            level=level,
            container=container,
            pod=pod,
            is_stack_trace=is_stack,
            stack_trace=stack_trace,
        )

    def _parse_json_line(self, data: dict, raw_line: str, line_number: int) -> LogEntry:
        """Parse structured JSON log entry."""
        # Find message
        message = ""
        for key in ["msg", "message", "log", "error", "event"]:
            if key in data and isinstance(data[key], str):
                message = data[key]
                break
        if not message:
            message = json.dumps(data)

        # Find level
        raw_level = ""
        for key in ["level", "severity", "loglevel", "type"]:
            if key in data and isinstance(data[key], str):
                raw_level = data[key]
                break
        level = LogLevel.from_str(raw_level) if raw_level else LogLevel.UNKNOWN

        # Find timestamp
        timestamp: Optional[datetime] = None
        for key in ["timestamp", "time", "ts", "@timestamp", "datetime"]:
            if key in data:
                val = data[key]
                if isinstance(val, (int, float)):
                    try:
                        # Seconds or milliseconds
                        ts_val = val if val < 10000000000 else val / 1000.0
                        timestamp = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                        break
                    except Exception:
                        pass
                elif isinstance(val, str):
                    ts, _ = self._extract_timestamp(val)
                    if ts:
                        timestamp = ts
                        break

        # Container / Pod
        container = data.get("container") or data.get("container_name")
        pod = data.get("pod") or data.get("pod_name")

        # Stack trace
        stack_trace = data.get("stack") or data.get("stack_trace") or data.get("exception")
        is_stack = bool(stack_trace)

        return LogEntry(
            line_number=line_number,
            raw=raw_line,
            message=message,
            timestamp=timestamp,
            level=level,
            container=container,
            pod=pod,
            is_stack_trace=is_stack,
            stack_trace=str(stack_trace) if stack_trace else None,
        )

    def _extract_timestamp(self, line: str) -> Tuple[Optional[datetime], str]:
        """Extract timestamp from the beginning of line if present."""
        for pattern, _ in TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts_str = m.group(1).strip()
                # Parse ts_str into datetime
                parsed_dt = self._parse_iso_or_custom(ts_str)
                if parsed_dt:
                    rest = line[m.end():].strip()
                    return parsed_dt, rest
        return None, line

    def _parse_iso_or_custom(self, ts_str: str) -> Optional[datetime]:
        """Try parsing timestamps across ISO and common standards."""
        # Clean RFC3339 nano timestamps (e.g. 9 decimal places -> 6 for python strptime/fromisoformat)
        clean_ts = re.sub(r"(\.\d{6})\d+", r"\1", ts_str)
        clean_ts = clean_ts.replace("Z", "+00:00")

        # 1. fromisoformat
        try:
            return datetime.fromisoformat(clean_ts)
        except Exception:
            pass

        # 2. Formats
        formats = [
            "%Y-%m-%d %H:%M:%S,%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except Exception:
                pass

        # Syslog format: "Oct 29 13:45:00" -> assume current year
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            current_year = datetime.now(timezone.utc).year
            return dt.replace(year=current_year)
        except Exception:
            pass

        return None

    def _extract_level(self, text: str) -> Tuple[LogLevel, str]:
        """Extract log level token from start or within brackets."""
        # Bracketed level: [ERROR], (WARN), etc.
        m_bracket = re.match(r"^\[([A-Z]+)\]\s*", text, re.IGNORECASE)
        if m_bracket:
            lvl = LogLevel.from_str(m_bracket.group(1))
            if lvl != LogLevel.UNKNOWN:
                return lvl, text[m_bracket.end():]

        # Plain level word at start: "ERROR - Connection failed" or "ERROR: Connection failed"
        m_word = re.match(r"^([A-Z]{3,8})[\s:\-\|]+\s*", text, re.IGNORECASE)
        if m_word:
            lvl = LogLevel.from_str(m_word.group(1))
            if lvl != LogLevel.UNKNOWN:
                return lvl, text[m_word.end():]

        # Search within first 30 chars
        prefix = text[:35]
        m_search = LEVEL_REGEX.search(prefix)
        if m_search:
            lvl = LogLevel.from_str(m_search.group(1))
            if lvl != LogLevel.UNKNOWN:
                return lvl, text

        return LogLevel.UNKNOWN, text
