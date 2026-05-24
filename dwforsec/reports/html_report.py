from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from dwforsec.reports.base_report import BaseReport
from dwforsec.utils.file_helpers import write_file_async

class HtmlReport(BaseReport):
    async def generate(self) -> Path:
        filename = self.get_filename("html")
        out_path = self.output_dir / "html" / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Resolve templates path
        templates_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        template = env.get_template("report.html")
        
        # Render HTML
        content = template.render(
            target=self.target,
            scan_id=self.scan_id,
            timestamp=self.timestamp,
            summary=self.data.get("summary", {}),
            subdomains=self.data.get("subdomains", []),
            findings=self.data.get("findings", []),
            ssl_findings=self.data.get("ssl_findings", []),
            js_analysis=self.data.get("js_analysis", [])
        )
        
        await write_file_async(out_path, content)
        return out_path
