from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class LogInput(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: Literal['linux', 'windows', 'sysmon'] = 'linux'
    hostname: str = Field(min_length=1, max_length=255)
    raw: str = Field(min_length=1, max_length=16384)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: int | None = None
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = None

    @field_validator('timestamp')
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError('timestamp must include a timezone')
        return value.astimezone(timezone.utc)

    @field_validator('source_ip')
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        if value:
            from ipaddress import ip_address
            return str(ip_address(value))
        return None


class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    hostname: str
    source: str
    event_type: str
    severity: str
    username: str | None = None
    source_ip: str | None = None
    raw: str


class Alert(BaseModel):
    id: str
    timestamp: datetime
    title: str
    severity: str
    hostname: str
    source_ip: str | None
    username: str | None
    technique_id: str
    technique_name: str
    description: str
    event_ids: list[str]
