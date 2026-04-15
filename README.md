# NetSentinel — Async TCP Port Scanner

```
 _   _      _   ____            _   _            _
| \ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
|  \| |/ _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
| |\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
|_| \_|\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|
```

[![C++20](https://img.shields.io/badge/C++-20-00599C?style=flat&logo=cplusplus)](https://isocpp.org)
[![CMake](https://img.shields.io/badge/CMake-3.15+-064F8C?style=flat&logo=cmake)](https://cmake.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)](https://github.com/deepmaha2006/NetSentinel)

> Asynchronous TCP port scanner built with **C++20** and **Boost.Asio** for high-concurrency network reconnaissance and service fingerprinting.

---

## What It Does

| Feature | Details |
|---|---|
| 🚀 **Async Scanning** | Uses Boost.Asio strand for concurrent, non-blocking port probing |
| 🔍 **State Detection** | Identifies OPEN, CLOSED, and FILTERED port states |
| 📡 **Banner Grabbing** | Reads initial service responses for version fingerprinting |
| 🗺️ **Service Mapping** | Maps 40+ well-known ports to service names |
| ⏱️ **Timeout Control** | Configurable timeout to detect firewall-filtered ports |
| 🎛️ **Concurrency Control** | Adjustable thread countBalances speed vs. stealth |

---

## Quick Start

### Requirements

| Tool | Version |
|---|---|
| C++ Compiler | GCC 10+, Clang 12+, or MSVC 2022 |
| CMake | 3.15+ |
| Boost | 1.74+ (program_options, system, asio) |

### Build & Run

```bash
# Clone the repo
git clone https://github.com/deepmaha2006/NetSentinel.git
cd NetSentinel

# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make -j4           # Linux/macOS
# or: cmake --build .   # Windows

# Run
./NetSentinel -i 127.0.0.1 -p 1-1024
```

### Windows (with vcpkg)
```powershell
# Install Boost via vcpkg
vcpkg install boost-asio boost-program-options boost-system

# Configure with vcpkg toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build . --config Release
```

---

## Usage

```
Usage: NetSentinel [options]

Options:
  -h, --help          Show help message
  -i, --dname         Target IP or domain  (default: 127.0.0.1)
  -p, --ports         Port range N or N-M  (default: 1-1024)
  -t, --threads       Max concurrent scans (default: 100)
  -e, --expiry_time   Timeout in seconds   (default: 2)
```

### Examples

```bash
# Scan localhost common ports
./NetSentinel -i 127.0.0.1 -p 1-1024

# Full scan of a target
./NetSentinel -i 192.168.1.1 -p 1-65535 -t 200

# Slower, stealthier scan with long timeout
./NetSentinel -i 10.0.0.5 -p 1-1024 -t 20 -e 5

# Test against nmap's public demo host
./NetSentinel -i scanme.nmap.org -p 1-1024 -t 50 -e 3

# Scan only web ports
./NetSentinel -i example.com -p 80-443 -e 3
```

### Sample Output

```
[*] Target   : scanme.nmap.org
[*] Ports    : 1-1024
[*] Threads  : 100
[*] Timeout  : 2s

PORT   STATE      SERVICE          BANNER
----   -----      -------          ------
22     OPEN       SSH              SSH-2.0-OpenSSH_6.6.1p1 Ubuntu...
80     OPEN       HTTP             ---
443    CLOSED     HTTPS            ---
135    FILTERED   MSRPC            ---

╔══════════════════════════════════╗
║           Scan Summary           ║
╠══════════════════════════════════╣
║  Open:      2                   ║
║  Closed:    998                 ║
║  Filtered:  24                  ║
╚══════════════════════════════════╝
```

---

## Architecture

```
main.cpp
  └── CLI parsing (Boost.Program_options)
      └── PortScanner::set_options()
          ├── parsePort()        - Parse "N" or "N-M" range
          └── resolver.resolve() - DNS lookup
              └── PortScanner::start()
                  └── post MAX_THREADS scan() to strand
                      └── scan() [recursive via strand]
                          ├── async_connect → OPEN/CLOSED
                          │     └── async_read_some → banner
                          └── async_wait (timer) → FILTERED
```

---

## Learn Modules

Step-by-step walkthroughs are in the [`learn/`](learn/) directory:

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites, quick start, project structure |
| [01 - Concepts](learn/01-CONCEPTS.md) | Security theory: port states, banner grabbing, real attacks |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | Async I/O design, strand executor, data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough, async patterns explained |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas: UDP, OS fingerprinting, stealth |

---

## ⚠️ Legal Notice

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized port scanning may be illegal in your jurisdiction and violates computer crime laws.
> This tool is intended for educational purposes and authorized security testing only.

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built by [deepmaha2006](https://github.com/deepmaha2006)*
