import json
import os
from datetime import datetime

def generate_json_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "scan_time": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

    json_path = os.path.join(output_dir, "scan_report.json")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=4)

    return json_path


def generate_html_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    html_path = os.path.join(output_dir, "scan_report.html")

    rows = ""
    for f in findings:
        rows += f"""
        <tr>
            <td>{f.get("severity")}</td>
            <td>{f.get("type")}</td>
            <td>{f.get("source")}</td>
            <td>{f.get("line")}</td>
            <td>{f.get("secret")}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>API Key Leakage Scanner Report</title>
        <style>
            body {{ font-family: Arial; background-color: #f4f4f4; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; background: #fff; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #222; color: #fff; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>API Key Leakage Scanner Report</h1>
        <p><strong>Scan Time:</strong> {datetime.utcnow().isoformat()}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>

        <table>
            <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Source</th>
                <th>Line</th>
                <th>Masked Secret</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(html_path, "w") as f:
        f.write(html)

    return html_path
