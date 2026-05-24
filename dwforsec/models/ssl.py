from pydantic import BaseModel, ConfigDict

class SSLFindingBase(BaseModel):
    host: str
    tls_version: str | None = None
    weak_ciphers: str | None = None
    hsts_enabled: bool | None = None
    self_signed: bool | None = None
    expiry_date: str | None = None
    issuer: str | None = None
    san: str | None = None
    recommendation: str | None = None

class SSLFindingCreate(SSLFindingBase):
    scan_id: int

class SSLFindingOut(SSLFindingBase):
    id: int
    scan_id: int

    model_config = ConfigDict(from_attributes=True)
