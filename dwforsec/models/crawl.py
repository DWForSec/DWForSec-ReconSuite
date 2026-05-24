from pydantic import BaseModel, ConfigDict

class CrawlResultBase(BaseModel):
    url: str
    content_type: str | None = None
    is_js: bool = False
    source_map_found: bool = False
    admin_route_found: bool = False
    staging_url_found: bool = False
    secrets_found: str | None = None

class CrawlResultCreate(CrawlResultBase):
    scan_id: int

class CrawlResultOut(CrawlResultBase):
    id: int
    scan_id: int

    model_config = ConfigDict(from_attributes=True)
