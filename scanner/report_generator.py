import json
import os
import html
from datetime import datetime


def generate_json_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings
    }

    json_path = os.path.join(output_dir, "scan_report.json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    return json_path


def generate_html_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    html_path = os.path.join(output_dir, "scan_report.html")

    rows = ""
    for f in findings:
        severity = html.escape(str(f.get("severity", "")))
        secret_type = html.escape(str(f.get("type", "")))
        source = html.escape(str(f.get("source", "")))
        line = html.escape(str(f.get("line", "")))
        secret = html.escape(str(f.get("secret", "")))

        severity_class = severity.lower()

        rows += f"""
        <tr class="{severity_class}">
            <td>{severity}</td>
            <td>{secret_type}</td>
            <td>{source}</td>
            <td>{line}</td>
            <td>{secret}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>API Key Leakage Scanner Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                padding: 20px;
            }}
            h1 {{
                color: #333;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                background: #fff;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #222;
                color: #fff;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr.critical {{ background-color: #ffcccc; }}
            tr.high {{ background-color: #ffe0b3; }}
            tr.medium {{ background-color: #ffffcc; }}
            tr.info {{ background-color: #e6f2ff; }}
        </style>
    </head>
    <body>
        <h1>API Key Leakage Scanner Report</h1>
        <p><strong>Scan Time:</strong> {datetime.utcnow().isoformat()}Z</p>
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

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return html_path
