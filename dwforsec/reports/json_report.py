import json
from pathlib import Path
from dwforsec.reports.base_report import BaseReport
from dwforsec.utils.file_helpers import write_file_async

class JsonReport(BaseReport):
    async def generate(self) -> Path:
        filename = self.get_filename("json")
        out_path = self.output_dir / "json" / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        content = json.dumps(self.data, indent=2)
        await write_file_async(out_path, content)
        return out_path
