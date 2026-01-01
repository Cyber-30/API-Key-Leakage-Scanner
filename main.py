from scanner.live_scanner import scan_website
from scanner.report_generator import generate_json_report, generate_html_report


def get_input(prompt, default=None):
    value = input(prompt).strip()
    if not value and default is not None:
        return default
    return value


def main():
    print("=== API Key Leakage Scanner (Live Website Mode) ===\n")

    target = get_input("Enter your target URL: ")

    # Auto-fix URL if scheme missing
    if not target.startswith(("http://", "https://")):
        print("[-] Invalid URL. Include http:// or https://")
        return

    try:
        max_pages = int(get_input("Maximum pages to crawl (default 10): ", "10"))
        delay = float(get_input("Request delay in seconds (default 1.0): ", "1.0"))
    except ValueError:
        print("[-] Invalid number entered.")
        return

    json_choice = get_input("Generate JSON report? (y/n, default y): ", "y").lower()
    html_choice = get_input("Generate HTML report? (y/n, default y): ", "y").lower()

    print("\n[*] Scanning website...\n")

    findings = scan_website(
        start_url=target,
        max_pages=max_pages,
        delay=delay
    )

    if json_choice == "y":
        json_path = generate_json_report(findings)
        print(f"[+] JSON report saved to: {json_path}")

    if html_choice == "y":
        html_path = generate_html_report(findings)
        print(f"[+] HTML report saved to: {html_path}")

    print("\n[+] Scan completed")
    print(f"[+] Total findings: {len(findings)}")


if __name__ == "__main__":
    main()
