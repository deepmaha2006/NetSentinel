# 03 - Implementation: Code Walkthrough

This document walks through the actual code, explaining async port scanning under the hood.

---

## File Structure

```
NetSentinel/
├── src/
│   ├── PortScanner.hpp     # Class definition: member vars, async primitives, method sigs
│   └── PortScanner.cpp     # Implementation: async scan logic, completion handlers, banner grab
├── main.cpp                # Entry point: CLI parsing, scanner init, blocking run()
└── CMakeLists.txt          # Build config: C++20, Boost dependencies
```

---

## Step 1: CLI Argument Parsing (`main.cpp`)

```cpp
po::options_description desc("Options");
desc.add_options()
    ("help,h",    "Show help message")
    ("dname,i",   po::value<std::string>()->default_value("127.0.0.1"), "Target IP or domain")
    ("ports,p",   po::value<std::string>()->default_value("1-1024"), "Port range N or N-M")
    ("threads,t", po::value<int>()->default_value(100), "Max concurrent threads")
    ("expiry_time,e", po::value<uint8_t>()->default_value(2)->value_name("sec"), "Timeout secs");
```

**Why Boost.Program_Options?**
- Type-safe: `-t hello` throws an exception instead of crashing
- Auto-generates `--help` output
- Short + long flags (`-i` and `--dname`) — standard Unix convention
- `uint8_t` for timeout enforces 0–255 range

---

## Step 2: Configuration → Scanner (`main.cpp`)

```cpp
std::string ip          = vm["dname"].as<std::string>();
std::string port        = vm["ports"].as<std::string>();
int         threads     = vm["threads"].as<int>();
uint8_t     expiry_time = vm["expiry_time"].as<uint8_t>();

PortScanner scanner;
scanner.set_options(ip, port, threads, expiry_time);
scanner.start();
scanner.run();
```

Default constructor + `set_options()` allows reusing a scanner for multiple scans.

---

## Step 3: Port Range Parsing (`PortScanner.cpp`)

```cpp
void PortScanner::parsePort(std::string& port) {
    auto dash = std::find(port.begin(), port.end(), '-');
    if (dash == port.end()) {
        startPort = 1;
        endPort   = static_cast<uint16_t>(std::stoi(port));  // "1024" = scan 1..1024
        return;
    }
    std::string s(port.begin(), dash);
    std::string e(dash + 1, port.end());
    int start = std::stoi(s);
    int end   = std::stoi(e);
    // Bounds check: invalid input falls back to full scan
    if (start < 1 || end > MAX_PORT || start > end) {
        startPort = 1; endPort = MAX_PORT;
    } else {
        startPort = static_cast<uint16_t>(start);
        endPort   = static_cast<uint16_t>(end);
    }
}
```

**Key:** Fail-safe design — bad input (`5000-100`) defaults to full scan rather than crashing.

---

## Step 4: The Core `scan()` Method (`PortScanner.cpp`)

This is the heart of the scanner. It's a self-scheduling async function:

```cpp
void PortScanner::scan() {
    // Guard: stop if no work or at thread limit
    if (portQueue.empty() || activeCount >= MAX_THREADS) return;

    uint16_t port = portQueue.front();
    portQueue.pop();
    ++activeCount;   // Track in-flight ops

    auto socket   = std::make_shared<tcp::socket>(io);
    auto timer    = std::make_shared<boost::asio::steady_timer>(io);
    auto complete = std::make_shared<bool>(false);   // Race flag

    tcp::endpoint target(endpoint.address(), port);
    timer->expires_after(std::chrono::seconds(expiryTime));
    // ... (timer + connect launched simultaneously)
}
```

### Shared Pointer Lifetime Management
```cpp
// Stack-allocated = USE AFTER FREE (CRASH)
tcp::socket socket(io);
timer->async_wait([&socket](...) { socket.close(); }); // socket gone when scan() returns!

// Shared pointer = SAFE
auto socket = std::make_shared<tcp::socket>(io);
timer->async_wait([socket](...) { socket->close(); }); // ref count keeps it alive
```

---

## Step 5: The Timer/Socket Race

Both fire simultaneously. Whichever completes first wins:

### Timer Handler (Filtered Detection)
```cpp
timer->async_wait(boost::asio::bind_executor(strand,
    [this, complete, socket, port](boost::system::error_code ec) {
        if (!ec && !*complete) {          // Timer fired naturally, not cancelled
            *complete = true;
            boost::system::error_code ignore;
            socket->close(ignore);         // Abort pending connect
            printf("%-6d FILTERED ...\n", port);
            ++filteredPorts;
            --activeCount;
            scan();                        // Grab next port
        }
    }));
```

### Connect Handler (Open / Closed)
```cpp
socket->async_connect(target, boost::asio::bind_executor(strand,
    [this, socket, timer, port, complete](boost::system::error_code ec) {
        if (*complete) return;   // Lost the race — timer already won
        *complete = true;
        timer->cancel();         // Won the race — stop timer

        if (!ec) {
            // OPEN — try banner grab
            auto buf = std::make_shared<std::array<char, 256>>();
            socket->async_read_some(boost::asio::buffer(*buf),
                boost::asio::bind_executor(strand,
                [this, port, buf, banner, svc]
                (boost::system::error_code ec, std::size_t n) {
                    if (!ec && n > 0) {
                        std::string raw(buf->data(), n);
                        // Strip whitespace, truncate long banners
                        *banner = raw.substr(0, 60);
                    }
                    printf("%-6d OPEN  %-16s %s\n", port, svc.c_str(), banner->c_str());
                    ++openPorts; --activeCount; scan();
                }));
        } else {
            // CLOSED — host sent RST
            printf("%-6d CLOSED %-16s ---\n", port, svc.c_str());
            ++closedPorts; --activeCount; scan();
        }
    }));
```

---

## Step 6: Strand Safety

Without strand → **race condition**:
```cpp
// WRONG: two handlers run concurrently → corrupted counter
socket->async_connect(endpoint, [this, port](...) {
    ++openPorts;  // DATA RACE if two handlers run simultaneously!
});
```

With strand → **serialized** (one handler at a time):
```cpp
// RIGHT: bind_executor(strand, ...) serializes all handlers
socket->async_connect(endpoint, boost::asio::bind_executor(strand,
    [this, port](...) {
        ++openPorts;  // Safe
    }));
```

---

## Full Trace: Port 22 (SSH) Open

```
1. set_options("192.168.1.100", "22", 100, 2)
   → DNS resolves, endpoint cached

2. setupQueue() → queue = [22]

3. start() → post MAX_THREADS scan() calls
   → 99 return immediately (guard: activeCount >= queue size)
   → 1 worker proceeds

4. scan():
   port = 22, activeCount = 1
   socket + timer created
   timer set to 2 seconds
   async_wait posted
   async_connect to 192.168.1.100:22 posted

5. On the wire:
   Scanner ──SYN──────► 192.168.1.100:22
   Scanner ◄──SYN-ACK── 192.168.1.100:22  (< 100ms typically)
   Scanner ──ACK──────► 192.168.1.100:22  (connection complete)

6. Connect handler fires (ec = success):
   *complete = true, timer->cancel()
   service = "SSH" (from knownServices map)
   async_read_some posted

7. SSH server sends: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

8. Read handler fires:
   banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
   printf("22     OPEN       SSH              SSH-2.0-OpenSSH_8.2p1...")
   ++openPorts, --activeCount
   scan() → portQueue empty → returns

9. io.run() returns → print summary
```

---

## Common Pitfalls

### Pitfall 1: Forgetting strand binding
```cpp
// WRONG - race condition on shared state
socket->async_connect(endpoint, [this](...) { ++openPorts; q.pop(); });

// RIGHT
socket->async_connect(endpoint, boost::asio::bind_executor(strand, [this](...) { ++openPorts; }));
```

### Pitfall 2: Capturing locals by reference
```cpp
// WRONG - port is gone when scan() returns
void scan() {
    uint16_t port = portQueue.front();
    async_connect(endpoint, [&port](...) { printf("%d\n", port); }); // use-after-free!
}

// RIGHT - copy by value
void scan() {
    uint16_t port = portQueue.front();
    async_connect(endpoint, [port](...) { printf("%d\n", port); }); // safe copy
}
```

---

## Debugging Tips

| Problem | Cause | Fix |
|---------|-------|-----|
| All ports show FILTERED | Firewall blocking you or target | Try `ping target`, reduce `-t`, increase `-e` |
| Segfault in Asio internals | Stack-allocated socket/timer | Use `std::make_shared<>` |
| Corrupted statistics | Missing strand binding | Wrap all handlers with `bind_executor(strand, ...)` |
| DNS fails immediately | Domain doesn't exist | Verify with `ping hostname` first |

---

## Next Steps
- Read [04-CHALLENGES.md](./04-CHALLENGES.md) for extension ideas
- Modify `MAX_THREADS` from 1 to 1000 and observe the effect
- Compare results with `nmap -sT scanme.nmap.org` (same scan type)
