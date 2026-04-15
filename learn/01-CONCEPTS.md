# 01 - Concepts: Port Scanning, States & Banner Grabbing

This document explains the security concepts behind this project — practical knowledge used daily in penetration testing and network defense.

---

## Port Scanning

### What It Is
Port scanning probes a target host to determine which TCP/UDP ports accept connections. Each port (0–65535) may have a service listening. Scanning reveals what software is running without authentication.

Think of ports like doors on a building — port scanning checks which ones are unlocked.

### Why It Matters
Port scanning is **reconnaissance**, the first phase of the cyber kill chain:
- **2017 Equifax breach** — started with finding an unpatched Apache Struts server on port 8080.
- **2016 Mirai botnet** — scanned the internet for Telnet (port 23) on IoT devices, then brute-forced default credentials. Took down Twitter, Netflix, and Reddit.

### How It Works (TCP Three-Way Handshake)

**OPEN port:**
```
Scanner ──SYN────────► Target
Scanner ◄────SYN-ACK── Target   (service is listening!)
Scanner ──RST────────► Target   (scanner aborts)
```

**CLOSED port:**
```
Scanner ──SYN────────► Target
Scanner ◄────RST────── Target   (host responded, nothing listening)
```

**FILTERED port:**
```
Scanner ──SYN────────► Target
         (silence)              (firewall dropped the packet)
```

---

## Port States

### Open
Something is listening. This is your attack surface.
- In the 2020 SolarWinds attack, attackers scanned for open RDP (3389) and WinRM (5985) to move laterally.

### Closed
Host is alive and reachable, but nothing listens. Confirms target exists.

### Filtered
A firewall sits between you and the target. Reveals security infrastructure.

### Implementation in NetSentinel (`src/PortScanner.cpp`)

**Open detection:**
```cpp
socket->async_connect(endpoint, [](boost::system::error_code ec) {
    if (!ec) {
        // Connection succeeded = OPEN
    }
});
```

**Closed detection:**
```cpp
else {
    // ec = "connection refused" = CLOSED
}
```

**Filtered detection (timer race):**
```cpp
timer->async_wait([](boost::system::error_code ec) {
    if (!ec && !*complete) {
        // Timer expired before connection = FILTERED
    }
});
```

---

## Banner Grabbing

### What It Is
After connecting to an open port, reading whatever initial message the service sends. Many protocols announce themselves:
- SSH: `SSH-2.0-OpenSSH_8.2p1`
- FTP: `220 ProFTPD 1.3.5 Server`
- SMTP: `220 mail.server.com ESMTP Postfix`

### Why It Matters
- **2014 Heartbleed (CVE-2014-0160)** — attackers banner-grabbed to identify OpenSSL 1.0.1–1.0.1f servers vulnerable to memory disclosure.
- **2021 ProxyLogon (Exchange)** — version banners identified which Exchange servers were exploitable before mass exploitation occurred.

### Implementation
```cpp
// src/PortScanner.cpp
auto buf = std::make_shared<std::array<char, 256>>();
socket->async_read_some(boost::asio::buffer(*buf),
    [](boost::system::error_code ec, std::size_t n) {
        if (!ec && n > 0) {
            banner->assign(buf->data(), n);
        }
        printf("%-6d OPEN  %-16s %s\n", port, service, banner->c_str());
    });
```

### Defense Strategies
- **Suppress version info:** SSH: `DebianBanner no`, Apache: `ServerTokens Prod`, Nginx: `server_tokens off`
- **Generic error messages:** Don't leak framework versions in error pages
- **Banner randomization / honeypots:** Fake vulnerable banners to waste attacker time

---

## The Reconnaissance Pipeline

```
Port Scan
    ↓
Identifies OPEN ports
    ↓
Banner Grab
    ↓
Reveals service versions
    ↓
Vulnerability Mapping
    ↓
Exploitation
```

---

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1046 – Network Service Discovery | Port scanning to discover services |
| T1595.001 – Active Scanning | Automated IP block scanning |

## OWASP Top 10 Mapping

| Item | Relevance |
|------|-----------|
| A05 – Security Misconfiguration | Unnecessary open ports |
| A01 – Broken Access Control | Services listening publicly that shouldn't be |

---

## Case Studies

### Mirai Botnet (2016)
1. Scanned internet for port 23/22
2. Grabbed banners to identify device types
3. Tried default credentials (admin/admin)
4. Infected and launched DDoS — took down Dyn DNS

**Prevention:** Disable Telnet, require password changes on first boot, ISP-level blocking of port 23.

### SolarWinds (2020)
Attackers used port scanning **inside** victim networks to:
1. Find RDP (3389), WinRM (5985), AD ports (88, 389, 636)
2. Identify backup systems to disable
3. Map network topology for targeted exfiltration

**Prevention:** East-west traffic analysis, network segmentation, deception technology.

---

## Test Your Understanding

1. Why does the scanner use **timeouts** to detect filtered ports instead of waiting for RST?
2. If an SSH banner says `OpenSSH_7.4`, what does an attacker know?
3. Why are **closed ports** still useful reconnaissance data?

---

## Further Reading

- **RFC 793** — TCP Specification (handshake behavior)
- **Nmap Network Scanning** by Gordon Lyon — available free at nmap.org/book/
- **IANA Port Registry** — iana.org/assignments/service-names-port-numbers/
- **Snort Rules** — snort.org/rules (scan detection patterns)
