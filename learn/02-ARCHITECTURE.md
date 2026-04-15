# 02 - Architecture: Design & Data Flow

---

## System Diagram

```
┌─────────────────────────────────────┐
│      Command Line Interface         │
│   (Boost.Program_Options Parser)    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│        PortScanner Object           │
│   - Configuration Management        │
│   - Work Queue (ports to scan)      │
│   - Thread/Concurrency Control      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│       Boost.Asio io_context         │
│    (Event Loop / Async Runtime)     │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐  ┌─────────────┐
│   Socket    │  │    Timer    │
│   (TCP      │  │  (Timeout   │
│ Connection) │  │  Detection) │
└─────────────┘  └─────────────┘
       │               │
       └───────┬───────┘
               ▼
       ┌───────────────┐
       │    Target     │
       │  Host:Port    │
       └───────────────┘
```

---

## Primary Scanning Flow

Step-by-step for `./NetSentinel -i 192.168.1.1 -p 80-443`:

```
1. main.cpp → Parse CLI args (IP, port range, threads, timeout)

2. PortScanner::set_options() → DNS resolve → cache endpoint

3. PortScanner::setupQueue() → Fill queue with ports 80..443 (364 entries)

4. PortScanner::start() → Post MAX_THREADS scan() calls to strand

5. main → run() → io.run() blocks until all async ops complete

6. scan() [called concurrently]:
   - Pop port from queue
   - Create socket + timer
   - Race: connect vs. timeout
     - Timer fires first → FILTERED
     - Connect success    → OPEN (then banner grab)
     - Connect error      → CLOSED
   - Decrement active count
   - Recurse: call scan() for next port

7. Queue empty → io.run() returns → print summary
```

---

## Key Design Patterns

### Async I/O with Completion Handlers

Instead of blocking on each connection, we start the operation and provide a callback:

```cpp
// PortScanner.cpp - core async connect
socket->async_connect(endpoint, boost::asio::bind_executor(strand,
    [this, socket, timer, port, complete](boost::system::error_code ec) {
        if (*complete) return;   // lost the race
        *complete = true;
        timer->cancel();
        if (!ec) { /* OPEN */ }
        else     { /* CLOSED */ }
        scan();  // grab next port
    }));
```

**Why async?**
- Sync scan at 100ms/port × 65535 = 1.8 hours
- Async with 100 workers × 100ms = ~66 seconds (**95× faster**)

---

### Work Queue with Fixed Concurrency

```
├── portQueue: [80, 81, 82, ... 443]
├── activeCount: tracks in-flight ops
└── MAX_THREADS: concurrency cap (default 100)
```

- `scan()` pops one port, increments `activeCount`, then calls itself recursively when done
- Guards: `if (portQueue.empty() || activeCount >= MAX_THREADS) return;`
- Natural load balancing — fast results (closed) grab the next port immediately

---

### Strand for Thread Safety

```cpp
// PortScanner.hpp
boost::asio::strand<boost::asio::io_context::executor_type> strand{io.get_executor()};

// All handlers wrapped:
boost::asio::bind_executor(strand, lambda)
```

**Why strand instead of mutex?**
Multiple handlers modify `openPorts`, `closedPorts`, `filteredPorts`, and `portQueue`. The strand serializes handler execution — no two handlers run simultaneously — eliminating data races without locks.

---

### Timer/Socket Race (Filtered Detection)

```
Port probe starts
    ├─► async_connect (may hang if filtered)
    └─► async_wait(expiryTime seconds)

Whichever fires first wins:
    - connect fires → timer cancelled → OPEN or CLOSED
    - timer fires   → socket closed  → FILTERED
```

`std::shared_ptr<bool> complete` acts as a one-shot flag — the loser handler sees `*complete == true` and exits immediately.

---

## Layered Architecture

```
┌────────────────────────────────────┐
│    Presentation Layer              │
│    - CLI parsing (main.cpp)        │
│    - Output formatting + colors    │
└────────────────────────────────────┘
           ↓
┌────────────────────────────────────┐
│    Business Logic Layer            │
│    - PortScanner class             │
│    - Async scan algorithm          │
│    - State tracking (counters)     │
└────────────────────────────────────┘
           ↓
┌────────────────────────────────────┐
│    I/O Layer                       │
│    - Boost.Asio runtime            │
│    - async_connect / async_wait    │
│    - steady_timer                  │
└────────────────────────────────────┘
```

**Separation of concerns** means:
- Want a GUI? Replace presentation layer, keep business logic.
- Want to swap Asio for raw POSIX sockets? Replace I/O layer.
- Want UDP scanning? Extend business logic without touching presentation.

---

## Key Design Decisions

### Connect Scan vs SYN Scan
We chose **full TCP connect** (complete three-way handshake).
- ✅ No root/admin privileges needed
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Works cleanly with Boost.Asio high-level API
- ❌ Noisier than SYN scan (shows in target logs as completed connections)

SYN scanning requires raw sockets → root privileges → implementation complexity. Connect scan is the right choice for a beginner/intermediate-level tool.

### Timeout vs ICMP for Filtered Detection
We chose **timeout-based** filtering detection.
- ✅ Works without privileges
- ✅ Works even when ICMP is blocked
- ✅ Simple to implement
- ❌ Adds latency (must wait full timeout)
- ❌ Can't distinguish "filtered" from "network down"

### Recursive scan() vs Worker Pool
We chose **recursive tail calls** within the strand.
- ✅ Minimal code
- ✅ Natural fit with async completion handlers
- ✅ No manual thread management
- ❌ Harder to implement advanced scheduling

---

## Performance Characteristics

| Scenario | Sync | Async (100 threads) |
|----------|------|---------------------|
| 1024 ports @ 100ms/port | 102 sec | ~1 sec |
| 65535 ports @ 100ms/port | 1.8 hrs | ~66 sec |
| 65535 ports @ 2s timeout | 36 hrs | ~22 min |

**Bottlenecks:**
1. **Network latency** dominates — can't scan faster than RTT
2. **DNS resolution** is synchronous at startup
3. **File descriptor limits** cap maximum concurrency (~1024 by default on Linux)

---

## Next Steps
- [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) — detailed code walkthrough
- Try removing the strand and observe race conditions
- Experiment with `-t 1` (serial) vs `-t 500` (aggressive)
