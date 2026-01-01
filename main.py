from scanner.live_scanner import scan_website
from scanner.report_generator import generate_json_report, generate_html_report
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]

    print("[*] Scanning website...")
    findings = scan_website(target)

    json_report = generate_json_report(findings)
    html_report = generate_html_report(findings)

    print("[+] Scan completed")
    print(f"[+] Total findings: {len(findings)}")
    print(f"[+] JSON report: {json_report}")
    print(f"[+] HTML report: {html_report}")

if __name__ == "__main__":
    main()
