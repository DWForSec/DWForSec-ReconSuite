from pydantic import BaseModel, ConfigDict

class SubdomainBase(BaseModel):
    subdomain: str
    ip_address: str | None = None
    is_live: bool = False
    status_code: int | None = None
    title: str | None = None

class SubdomainCreate(SubdomainBase):
    scan_id: int

class SubdomainOut(SubdomainBase):
    id: int
    scan_id: int

    model_config = ConfigDict(from_attributes=True)
