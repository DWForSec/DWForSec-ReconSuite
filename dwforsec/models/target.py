import datetime
from pydantic import BaseModel, ConfigDict

class TargetBase(BaseModel):
    domain: str

class TargetCreate(TargetBase):
    pass

class TargetOut(TargetBase):
    id: int
    created_at: datetime.datetime
    
    model_config = ConfigDict(from_attributes=True)
