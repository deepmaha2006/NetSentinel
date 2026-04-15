/**
 * PortScanner.cpp
 * Implementation of asynchronous TCP port scanning with banner grabbing.
 *
 * Core flow per port:
 *   1. Pop port from queue
 *   2. Launch async_connect + timer concurrently on the strand
 *   3. whichever fires first (connect or timeout) determines the state:
 *        - connect success  → OPEN  (then attempt async_read for banner)
 *        - connect error    → CLOSED (host sent RST)
 *        - timer fires first → FILTERED (firewall silently dropped packet)
 *   4. Decrement active count, recurse to pick next port from queue
 */

#include "PortScanner.hpp"

// ─── Well-known port → service name map ─────────────────────────────────────

const std::unordered_map<uint16_t, std::string> PortScanner::knownServices {
    {20,   "FTP-DATA"},
    {21,   "FTP"},
    {22,   "SSH"},
    {23,   "Telnet"},
    {25,   "SMTP"},
    {53,   "DNS"},
    {67,   "DHCP-Server"},
    {68,   "DHCP-Client"},
    {80,   "HTTP"},
    {110,  "POP3"},
    {119,  "NNTP"},
    {123,  "NTP"},
    {135,  "MSRPC"},
    {139,  "NetBIOS"},
    {143,  "IMAP"},
    {161,  "SNMP"},
    {194,  "IRC"},
    {389,  "LDAP"},
    {443,  "HTTPS"},
    {445,  "SMB"},
    {465,  "SMTPS"},
    {514,  "Syslog"},
    {587,  "SMTP-Submit"},
    {636,  "LDAPS"},
    {993,  "IMAPS"},
    {995,  "POP3S"},
    {1080, "SOCKS"},
    {1194, "OpenVPN"},
    {1433, "MSSQL"},
    {1521, "Oracle-DB"},
    {2181, "Zookeeper"},
    {3000, "HTTP-Dev"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {4444, "Metasploit"},
    {5432, "PostgreSQL"},
    {5900, "VNC"},
    {5985, "WinRM-HTTP"},
    {5986, "WinRM-HTTPS"},
    {6379, "Redis"},
    {6443, "Kubernetes-API"},
    {8080, "HTTP-Alt"},
    {8443, "HTTPS-Alt"},
    {8888, "HTTP-Jupyter"},
    {9200, "Elasticsearch"},
    {9300, "Elasticsearch-Cluster"},
    {27017,"MongoDB"},
};

// ─── Port parsing ────────────────────────────────────────────────────────────

void PortScanner::parsePort(std::string& port) {
    auto dash = std::find(port.begin(), port.end(), '-');
    if (dash == port.end()) {
        // Single number: scan 1..N
        startPort = 1;
        endPort   = static_cast<uint16_t>(std::stoi(port));
        return;
    }

    std::string s(port.begin(), dash);
    std::string e(dash + 1, port.end());

    int start = std::stoi(s);
    int end   = std::stoi(e);

    if (start < 1 || end > MAX_PORT || start > end) {
        // Fall back to full scan on bad input
        startPort = 1;
        endPort   = MAX_PORT;
    } else {
        startPort = static_cast<uint16_t>(start);
        endPort   = static_cast<uint16_t>(end);
    }
}

// ─── Constructors / configuration ───────────────────────────────────────────

PortScanner::PortScanner(std::string& ipAddress, std::string& port,
                         int maxThreads, std::uint8_t expiry) {
    set_options(ipAddress, port, maxThreads, expiry);
}

void PortScanner::set_options(std::string& domain, std::string& port,
                              int maxThreads, std::uint8_t expiry) {
    domainName  = std::move(domain);
    MAX_THREADS = maxThreads;
    expiryTime  = expiry;

    parsePort(port);

    auto result = resolver.resolve(domainName, "");
    endpoint    = *result.begin();
}

void PortScanner::set_max_port(std::uint16_t port)    { endPort      = port;   }
void PortScanner::set_max_threads(int value)           { MAX_THREADS  = value;  }
void PortScanner::set_ip_address(std::string ip)       { domainName   = std::move(ip); }
void PortScanner::set_expiry_time(std::uint8_t value)  { expiryTime   = value;  }

// ─── Queue setup ─────────────────────────────────────────────────────────────

void PortScanner::setupQueue() {
    portQueue = std::queue<uint16_t>();
    for (int p = startPort; p <= endPort; ++p) {
        portQueue.push(static_cast<uint16_t>(p));
    }
}

// ─── Public: start + run ─────────────────────────────────────────────────────

void PortScanner::start() {
    setupQueue();
    // Seed the strand with MAX_THREADS initial scan() calls
    for (int i = 0; i < MAX_THREADS; ++i) {
        boost::asio::post(strand, [this]() { scan(); });
    }
}

void PortScanner::run() {
    printf("%-6s %-10s %-16s %s\n", "PORT", "STATE", "SERVICE", "BANNER");
    printf("%-6s %-10s %-16s %s\n", "----", "-----", "-------", "------");
    io.run();   // Block until all async work is done

    printf("\n%s╔══════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║           Scan Summary           ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╠══════════════════════════════════╣%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║%s  %-10s %s%-20d%s║%s\n",
           COLOR_CYAN, COLOR_RESET, "Open:",
           COLOR_GREEN, openPorts, COLOR_CYAN, COLOR_RESET);
    printf("%s║%s  %-10s %s%-20d%s║%s\n",
           COLOR_CYAN, COLOR_RESET, "Closed:",
           COLOR_RED, closedPorts, COLOR_CYAN, COLOR_RESET);
    printf("%s║%s  %-10s %s%-20d%s║%s\n",
           COLOR_CYAN, COLOR_RESET, "Filtered:",
           COLOR_YELLOW, filteredPorts, COLOR_CYAN, COLOR_RESET);
    printf("%s╚══════════════════════════════════╝%s\n\n", COLOR_CYAN, COLOR_RESET);
}

// ─── Core async scan logic ───────────────────────────────────────────────────

void PortScanner::scan() {
    // Guard: nothing left in queue or concurrency cap hit
    if (portQueue.empty() || activeCount >= MAX_THREADS) return;

    uint16_t port = portQueue.front();
    portQueue.pop();
    ++activeCount;

    auto socket   = std::make_shared<tcp::socket>(io);
    auto timer    = std::make_shared<boost::asio::steady_timer>(io);
    auto complete = std::make_shared<bool>(false);

    tcp::endpoint target(endpoint.address(), port);
    timer->expires_after(std::chrono::seconds(expiryTime));

    // ── Timeout handler: fires if connection takes too long = FILTERED ──
    timer->async_wait(boost::asio::bind_executor(strand,
        [this, complete, socket, port](boost::system::error_code ec) {
            if (!ec && !*complete) {
                *complete = true;
                boost::system::error_code ignore;
                socket->close(ignore);

                std::string svc = "---";
                auto it = knownServices.find(port);
                if (it != knownServices.end()) svc = it->second;

                printf("%-6d %s%-10s%s %-16s %s\n",
                       port, COLOR_YELLOW, "FILTERED", COLOR_RESET,
                       svc.c_str(), "---");
                ++filteredPorts;
                --activeCount;
                scan();   // recurse to next port
            }
        }));

    // ── Connect handler: success = OPEN, error = CLOSED ─────────────────
    socket->async_connect(target, boost::asio::bind_executor(strand,
        [this, socket, timer, port, complete](boost::system::error_code ec) {
            if (*complete) return;   // timer already fired
            *complete = true;
            timer->cancel();

            std::string svc = "---";
            auto it = knownServices.find(port);
            if (it != knownServices.end()) svc = it->second;

            if (!ec) {
                // Port is OPEN — try banner grab
                auto buf    = std::make_shared<std::array<char, 256>>();
                auto banner = std::make_shared<std::string>("---");

                socket->async_read_some(boost::asio::buffer(*buf),
                    boost::asio::bind_executor(strand,
                    [this, port, buf, banner, svc]
                    (boost::system::error_code ec, std::size_t n) {
                        if (!ec && n > 0) {
                            // Strip newlines/carriage returns for clean output
                            std::string raw(buf->data(), n);
                            raw.erase(std::remove_if(raw.begin(), raw.end(),
                                [](char c){ return c == '\r' || c == '\n'; }),
                                raw.end());
                            // Truncate long banners
                            if (raw.size() > 60) raw = raw.substr(0, 60) + "...";
                            *banner = raw;
                        }
                        printf("%-6d %s%-10s%s %-16s %s\n",
                               port, COLOR_GREEN, "OPEN", COLOR_RESET,
                               svc.c_str(), banner->c_str());
                        ++openPorts;
                        --activeCount;
                        scan();
                    }));
            } else {
                // Port is CLOSED — host sent RST
                printf("%-6d %s%-10s%s %-16s %s\n",
                       port, COLOR_RED, "CLOSED", COLOR_RESET,
                       svc.c_str(), "---");
                ++closedPorts;
                --activeCount;
                scan();
            }
        }));
}
