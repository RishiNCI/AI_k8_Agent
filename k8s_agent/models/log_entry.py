"""Log entry data structures."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> "LogLevel":
        v = val.strip().upper()
        if v in ("DEBUG", "DBG"):
            return cls.DEBUG
        if v in ("INFO", "INF"):
            return cls.INFO
        if v in ("WARN", "WARNING", "WRN"):
            return cls.WARN
        if v in ("ERROR", "ERR"):
            return cls.ERROR
        if v in ("CRITICAL", "FATAL", "PANIC", "EMERG"):
            return cls.CRITICAL
        return cls.UNKNOWN

    @property
    def is_error_or_higher(self) -> bool:
        return self in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL)

    @property
    def is_warn_or_higher(self) -> bool:
        return self in (LogLevel.WARN, LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL)


class LogEntry(BaseModel):
    line_number: int
    raw: str
    message: str
    timestamp: Optional[datetime] = None
    level: LogLevel = LogLevel.UNKNOWN
    container: Optional[str] = None
    pod: Optional[str] = None
    namespace: Optional[str] = None
    is_stack_trace: bool = False
    stack_trace: Optional[str] = None

    @property
    def formatted_timestamp(self) -> str:
        if self.timestamp:
            return self.timestamp.isoformat()
        return "N/A"
