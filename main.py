from scanner.live_scanner import scan_website
from scanner.report_generator import generate_json_report, generate_html_report
from scanner.file_finder import find_files
from scanner.secret_scanner import scan_text


def get_input(prompt, default=None):
    value = input(prompt).strip()
    if not value and default is not None:
        return default
    return value


def main():
    print("=== API Key Leakage Scanner ===\n")

    mode = get_input("Select mode - live (website) or local (files) [live/local] (default live): ", "live").lower()

    json_choice = get_input("Generate JSON report? (y/n, default y): ", "y").lower()
    html_choice = get_input("Generate HTML report? (y/n, default y): ", "y").lower()

    findings = []
    global_seen = set()

    if mode == "local":
        base_path = get_input("Enter directory to scan (default .): ", ".")
        print(f"\n[*] Scanning local files under: {base_path}\n")

        files = find_files(base_path)

        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            findings += scan_text(content, fp, global_seen)

    else:
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
