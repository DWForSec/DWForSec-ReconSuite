import datetime
from pydantic import BaseModel, ConfigDict
from dwforsec.core.constants import Severity

class FindingBase(BaseModel):
    tool: str
    template_id: str | None = None
    matched_url: str | None = None
    host: str | None = None
    severity: Severity
    description: str | None = None
    recommendation: str | None = None

class FindingCreate(FindingBase):
    scan_id: int

class FindingOut(FindingBase):
    id: int
    scan_id: int
    discovered_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)
