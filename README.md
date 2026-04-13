# NetSentinel 🛡️

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-557C94?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A fast, multi-threaded network vulnerability scanner with automated report generation**

</div>

---

## 🔍 What is NetSentinel?

NetSentinel is a Python-based network vulnerability scanner designed for penetration testers and security auditors. It rapidly scans target hosts for open ports, identifies running services through banner grabbing, correlates findings against known CVEs, and produces professional vulnerability reports.

## ✨ Features

- **⚡ Fast Multi-threaded Scanning** — Configurable thread pool for speed
- **🔎 Banner Grabbing** — Identify exact service versions
- **⚠️ CVE Correlation** — Maps open services to known vulnerabilities
- **📄 Auto Report Generation** — TXT and JSON reports
- **🎨 Color Terminal Output** — Easy-to-read real-time results
- **🎯 Interactive & CLI Mode** — Flexible usage

## 📸 Demo

```
 ███╗   ██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
     ...

[*] Target    : 192.168.1.1 (192.168.1.1)
[*] Port Range: 1 - 1024
[*] Threads   : 100

  [OPEN]  Port    22/tcp  SSH             SSH-2.0-OpenSSH_8.9p1
  [OPEN]  Port    80/tcp  HTTP            HTTP/1.1 200 OK Server: Apache
  [OPEN]  Port   443/tcp  HTTPS           No banner
  [OPEN]  Port  3306/tcp  MySQL           [VULN]

Progress: [████████████████████████████████████████] 1024/1024

[+] Scan complete in 8.34s | 4 open port(s) found
```

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/deepmaha2006/NetSentinel.git
cd NetSentinel

# Install dependencies
pip install -r requirements.txt

# Run scanner
python scanner.py
```

## 💻 Usage

```bash
# Interactive mode
python scanner.py

# Scan specific host (default port range 1-1024)
python scanner.py 192.168.1.1

# Scan with custom port range
python scanner.py 192.168.1.1 1 65535

# Full scan example
python scanner.py scanme.nmap.org 1 1024
```

## 📊 Output

NetSentinel generates two report formats:

**Text Report (`report_<target>_<timestamp>.txt`)**
```
======================================================================
           NETSENTINEL - VULNERABILITY SCAN REPORT
======================================================================
Target Host  : 192.168.1.1
IP Address   : 192.168.1.1
Open Ports   : 4
...
  [!] VULNERABILITY: CVE-2012-2122 - Authentication bypass | Check for default credentials
  Risk    : HIGH
```

**JSON Report** — Machine-readable format for integration with other tools

## 🗂️ Project Structure

```
NetSentinel/
├── scanner.py          # Main scanner module
├── requirements.txt    # Python dependencies
├── README.md           # Documentation
└── reports/            # Auto-generated scan reports
```

## ⚠️ Legal Disclaimer

> This tool is intended **only for authorized penetration testing and educational purposes**. Scanning systems without explicit permission is illegal. The author is not responsible for any misuse.

## 👤 Author

**Deepesh Kumar Mahawar**
- GitHub: [@deepmaha2006](https://github.com/deepmaha2006)
- Email: deepeshmahawar2006@gmail.com

---

<div align="center">
Made with ❤️ and Python | ⭐ Star this repo if you found it useful!
</div>
