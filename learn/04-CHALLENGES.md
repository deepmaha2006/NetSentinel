# 04 - Challenges: Extend NetSentinel

You've built a concurrent async TCP port scanner. Now make it production-ready.

Challenges are ordered by difficulty. Complete earlier ones before tackling harder ones.

---

## Easy Challenges

### Challenge 1: CSV Output
Add `-o results.csv` flag to write scan results to a file.

**Why:** Security teams need machine-readable output for Excel, databases, Python scripts.

**Hints:**
- Add option in `main.cpp`: `("output,o", po::value<std::string>(), "output CSV file")`
- Modify completion handlers to write `port,state,service,banner` lines to a file stream
- CSV format: escape quotes and commas in banner strings

**Test:**
```bash
./NetSentinel -i scanme.nmap.org -p 1-1024 -o results.csv
cat results.csv
# 22,OPEN,SSH,SSH-2.0-OpenSSH_...
```

---

### Challenge 2: Progress Indicator
Show percentage completion during long scans.

**Why:** Full 65535-port scans take minutes. Users think the tool hung.

**Hints:**
- Track `scannedCount`/`totalPorts`, update every 100 results
- Use `\r` to overwrite the current line:
  ```cpp
  printf("\rProgress: %d/%d (%.1f%%)", scanned, total, pct);
  fflush(stdout);
  ```

---

### Challenge 3: Scan Multiple Hosts
Accept comma-separated targets: `-i 192.168.1.1,192.168.1.2`

**Why:** Pentesting requires scanning entire subnets.

**Hints:**
- Create `parseHosts()` that splits on commas → vector of endpoints
- Print host IP with each result line so you know which host a port belongs to

---

## Intermediate Challenges

### Challenge 4: JSON Output
Add `--format json` for structured output compatible with security toolchains.

**Output format:**
```json
{
  "target": "192.168.1.1",
  "scan_time": "2026-04-15T10:00:00Z",
  "ports_scanned": 1024,
  "results": [
    {"port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.2p1"},
    {"port": 80, "state": "closed", "service": "HTTP", "banner": null}
  ]
}
```

**Hints:**
- Use `nlohmann/json` library (header-only, add to CMakeLists.txt via FetchContent)
- Collect results in `std::vector<ScanResult>` instead of printing inline
- Print JSON summary in `run()` after `io.run()` completes

---

### Challenge 5: Service Version Detection
Send protocol-specific probes to identify exact software versions even when banners are suppressed.

**Probe examples:**
- Port 80: Send `GET / HTTP/1.0\r\n\r\n`, parse `Server:` header
- Port 21: Read banner, send `SYST\r\n`, parse system type
- Port 25: Send `EHLO scanner\r\n`, parse capabilities

**Why:** Many hardened servers disable banners. Active probing extracts versions for CVE matching.

---

## Advanced Challenges

### Challenge 6: SYN Scan
Implement half-open scanning — send SYN, read SYN-ACK, send RST (don't complete handshake).

**Why harder:** Requires raw sockets → root/admin privileges, manual TCP packet construction.

**Steps:**
1. Create raw socket: `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` (Linux only, needs root)
2. Build TCP SYN packet manually (IP header + TCP header + checksum)
3. Send with `sendto()`
4. Capture SYN-ACK responses with `recvfrom()` or libpcap

**Gotchas:**
- TCP checksum calculation requires pseudo-header (easy to get wrong)
- Kernel sends RST after SYN-ACK automatically — normal behavior
- Windows requires different raw socket API (Winsock2 + WinPcap)

---

### Challenge 7: OS Fingerprinting
Guess the target OS by analyzing TCP/IP behavior: TTL values, window size, TCP options.

**Signatures:**
| OS | Initial TTL | Window Size | TCP Options |
|----|-------------|-------------|-------------|
| Linux 5.x | 64 | 29200 | M*,S,T,N,W* |
| Windows 10 | 128 | 8192 | M*,N,W*,S,T |
| macOS | 64 | 65535 | M*,N,W*,S,T |
| FreeBSD | 64 | 65535 | M*,N,S,T,W* |

**Scoring:**
```cpp
int score = 0;
if (ttl_matches)     score += 50;
if (window_matches)  score += 30;
if (options_match)   score += 20;
// score >= 70 → high confidence
```

---

## Expert Challenges

### Challenge 8: Full Nmap-Style Scanner
Support multiple scan types (SYN, ACK, FIN, Xmas, NULL), timing templates (T0–T5), and scripting.

**Estimated time:** 4–6 weeks minimum.

**Timing templates:**
- T0 Paranoid: 5-minute delays (extreme IDS evasion)
- T1 Sneaky: serialized with pauses
- T2 Polite: reduced network load
- T3 Normal: current default
- T4 Aggressive: faster timeouts, more parallelism
- T5 Insane: maximum speed

---

### Challenge 9: IDS Evasion
Implement fragmentation, decoy scanning, source port manipulation, and timing randomization.

**Techniques:**
1. **Packet Fragmentation** — split TCP packets across multiple IP fragments
2. **Decoy Scanning** — mix real IP with fake source IPs
   ```
   Decoy:  10.0.0.50:12345 → target:80
   Real:   10.0.0.100:12346 → target:80  ← actual scanner
   Decoy:  10.0.0.125:12347 → target:80
   ```
3. **Timing Randomization** — random 50–150ms intervals instead of regular bursts

---

## Project Ideas (Combine Challenges)

| Project | Challenges Needed |
|---------|-------------------|
| Cloud Security Scanner | 3 + 4 + 5 + AWS Lambda |
| Continuous Monitor Dashboard | 2 + 4 + web UI + cron |
| Auto-Exploitation Pipeline | 5 + Metasploit RPC API |

---

## Performance Optimization Track

### Handle 100,000 Concurrent Connections
**Bottleneck:** Linux default FD limit = 1024 open files  
**Fix:** `ulimit -n 100000` or modify `/etc/security/limits.conf`

### Reduce Bandwidth Usage
- Reduce timeout from 2s to 1s on fast networks
- Only grab banners for interesting ports (22, 80, 443, 3306)
- Implement adaptive timeout based on measured RTT

### Add Attribution Watermark (Ethical)
```cpp
// HTTP probe that identifies your scanner in logs
"GET / HTTP/1.1\r\n"
"Host: " + target + "\r\n"
"User-Agent: NetSentinel/1.0 (Educational; Contact: your@email.com)\r\n"
"\r\n"
```

---

## Challenge Progress Tracker

- [ ] Easy 1: CSV Output
- [ ] Easy 2: Progress Indicator
- [ ] Easy 3: Multiple Hosts
- [ ] Intermediate 4: JSON Output
- [ ] Intermediate 5: Service Version Detection
- [ ] Advanced 6: SYN Scan
- [ ] Advanced 7: OS Fingerprinting
- [ ] Expert 8: Full Scan Engine
- [ ] Expert 9: IDS Evasion

---

## Study Real Implementations

| Tool | Why Study |
|------|-----------|
| [Nmap](https://github.com/nmap/nmap) | Edge case handling, scan techniques |
| [masscan](https://github.com/robertdavidgraham/masscan) | Extreme async performance |
| [ZMap](https://github.com/zmap/zmap) | Simple high-performance pattern |

---

> **Remember:** Only scan systems you own or have explicit written permission to test.
