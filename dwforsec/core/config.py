import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

BASE_DIR = Path("g:/tools hacking/tools reconsuite").resolve()

class Settings(BaseSettings):
    DATABASE_URL: str = Field(default=f"sqlite:///{BASE_DIR}/outputs/dwforsec.db")
    LOG_LEVEL: str = Field(default="INFO")
    REPORT_OUTPUT_DIR: str = Field(default=f"{BASE_DIR}/outputs/reports")
    REPORT_THEME: str = Field(default="dark")
    DEFAULT_REPORT_FORMAT: str = Field(default="html")
    MASK_SECRETS: bool = Field(default=True)
    REVEAL_SECRETS: bool = Field(default=False)
    MAX_CONCURRENCY: int = Field(default=5)
    COMMAND_TIMEOUT: int = Field(default=300)
    PUBLIC_ONLY: bool = Field(default=False)
    
    # Path to tools binaries directory
    TOOLS_DIR: str = Field(default=f"{BASE_DIR}/dwforsec/tools")

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# Ensure output directories exist
for sub in ["scans", "reports", "reports/html", "reports/pdf", "reports/markdown", "reports/json", "reports/txt", "logs", "temp"]:
    Path(BASE_DIR / "outputs" / sub).mkdir(parents=True, exist_ok=True)
Path(settings.TOOLS_DIR).mkdir(parents=True, exist_ok=True)
