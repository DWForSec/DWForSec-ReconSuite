from abc import ABC, abstractmethod
from pathlib import Path
from dwforsec.core.config import settings

class BaseReport(ABC):
    def __init__(self, scan_data: dict):
        self.data = scan_data
        self.target = scan_data.get("target", "unknown")
        self.scan_id = scan_data.get("scan_id", "unknown")
        self.timestamp = scan_data.get("timestamp", "unknown")
        self.output_dir = Path(settings.REPORT_OUTPUT_DIR)
        
    @abstractmethod
    async def generate(self) -> Path:
        """
        Generates the report file and returns its path.
        """
        pass
        
    def get_filename(self, ext: str) -> str:
        """
        Returns naming convention: dwforsec-report-{target}-{timestamp}.{ext}
        """
        # Replace characters that might be invalid in filename
        safe_target = self.target.replace("/", "_").replace(":", "_")
        return f"dwforsec-report-{safe_target}-{self.timestamp}.{ext}"
