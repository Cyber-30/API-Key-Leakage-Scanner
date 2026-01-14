# 🔐 API Key Leakage Scanner

A lightweight security tool to **detect exposed API keys, tokens, and secrets** in live websites by crawling pages and scanning JavaScript files using regex-based detection.

This project is designed for **bug bounty hunters, security engineers, and students** to understand real-world client-side secret exposure.

---

## 🚀 Features

- 🌐 Live website crawling (same-domain only)
- 📜 JavaScript file discovery & scanning
- 🔍 Regex-based detection of secrets
- 🧠 Severity classification (Critical → Info)
- 🛡️ Scope-restricted & bug-bounty safe
- 🐢 Rate-limited requests (ethical scanning)
- 📊 JSON + HTML reporting
- 🧑‍💻 Interactive CLI (no flags needed)

---

## 🧪 Detected Secret Types

| Secret Type | Severity |
|------------|----------|
| AWS Access Key | CRITICAL |
| AWS Secret Key | CRITICAL |
| JWT Tokens | HIGH |
| Bearer Tokens | HIGH |
| Generic API Keys | MEDIUM |

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/API-Key-Leakage-Scanner.git
cd API-Key-Leakage-Scanner
```

### 2️⃣ Install dependencies
```bash
pip install -r requirements.txt

```

### ▶️ Usage
Start the tool:
```bash
python3 main.py
```

You will be prompted step by step:
```bash
Enter your target URL:
Maximum pages to crawl:
Request delay in seconds:
Generate JSON report? (y/n)
Generate HTML report? (y/n)
```
---
### 📊 Output
After the scan, reports are generated in the reports/ directory.

## JSON Report
-  Machine-readable
-  Suitable for automation & CI

## HTML Report
-  Human-readable
-  Perfect for demos, screenshots and reports

---

### 🧪 Safe Testing Targets
The tool should be tested only on allowed targets, such as:
-  OWASP Juice Shop demo: https://demo.owasp-juice.shop
-  ❌ Do NOT scan websites without permission.
---
### 🛡️ Ethical Notice
This tool:
-  Does NOT exploit vulnerabilities
-  Does not brute-force or fuzz
-  Performs read-only analysis

You are responsible for following:
-  bug bounty rules
-  Legal and ethical guidelines
---
### 🎓 Learning Outcomes
By building this project, you learn:
-  Web crawling fundamentals
-  JavaScripts security risks
-  Regex-Based secret detection
-  False-positive reduction
-  Ethical security scanning
-  Report generation
---
### 📌 Future Improvements
-  False-positive suppression
-  Minfied JS chunk scanning
-  RAW file (Github / Pastebin) scanning
-  GitHub Actions integration
-  BURP/ZAP plugin support
---
### 👨‍💻 Author
Cyber-30
Cybersecurity Enthisiast | Bug Bounty Learner | CS Student
---
---
### ⭐ If you like this project
Give is a ⭐ on GitHub - it motivates further development!
---