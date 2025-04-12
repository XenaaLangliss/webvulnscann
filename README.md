# Web Vulnerability Scanner v1.0

---

Advanced web application security scanner with built-in exploitation capabilities for penetration testers and security researchers.

---

## 🔍 Features

### Scanning Capabilities
- **SQL Injection** (Time-Based, Error-Based, Boolean-Based)
- **Cross-Site Scripting** (XSS, DOM-Based XSS)
- **Local File Inclusion** (LFI with path traversal)
- **Remote Code Execution** (RCE detection)
- **Auto-Detection** of database types (MySQL, MSSQL, Oracle)

### Exploitation Modules
- Database schema extraction
- Credential dumping via UNION attacks
- XSS keylogger payload generation
- LFI to RCE conversion via log poisoning
- Automatic PoC generation

### Reporting
- JSON reports for tool integration
- Detailed text reports for manual review
- Proof-of-Concept (PoC) files storage
- Color-coded terminal output

---

## 🚀 Installation

### Requirements
- Python 3.7+
- Linux / Windows / macOS
- Internet connection

### Setup
```bash
# Clone repository
git clone https://github.com/XenaaLangliss/webvulnscann.git
cd webvulnscann

# Install dependencies
pip install -r requirements.txt
```

---

## 🛠 Usage

### Basic Scan
```bash
python3 scanner.py http://target.com
```

### Full Scan with Exploitation
```bash
python3 scanner.py http://target.com -e
```

### Advanced Options
```bash
python3 scanner.py http://target.com -e -v -o /custom/path
```

| Option | Description                          | Default   |
|--------|--------------------------------------|-----------|
| `-e`, `--exploit` | Enable auto-exploitation         | False     |
| `-o`, `--output`  | Custom reports directory         | ./reports |
| `-v`, `--verbose` | Show detailed scan progress      | False     |

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes only**. Usage against targets without proper authorization is **strictly prohibited**.

---
