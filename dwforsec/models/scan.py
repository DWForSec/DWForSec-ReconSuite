import datetime
from pydantic import BaseModel, ConfigDict

class ScanBase(BaseModel):
    target_id: int
    status: str = "running"

class ScanCreate(ScanBase):
    pass

class ScanOut(ScanBase):
    id: int
    started_at: datetime.datetime
    completed_at: datetime.datetime | None = None

    model_config = ConfigDict(from_attributes=True)
