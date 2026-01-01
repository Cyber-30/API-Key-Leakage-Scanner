import json
import os
from datetime import datetime

def generate_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "scan_time": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

    report_path = os.path.join(output_dir, "scan_report.json")

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    return report_path
