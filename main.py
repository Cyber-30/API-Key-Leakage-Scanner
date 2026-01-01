import sys
from scanner.live_scanner import scan_website
from scanner.report_generator import generate_report

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]

    print("[*] Scanning website in live mode...")
    findings = scan_website(target)

    report_path = generate_report(findings)

    print("[+] Scan completed")
    print(f"[+] Total findings: {len(findings)}")
    print(f"[+] Report saved to: {report_path}")

if __name__ == "__main__":
    main()
