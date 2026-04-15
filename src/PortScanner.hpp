/**
 * PortScanner.hpp
 * Header for the async TCP port scanner class.
 *
 * Uses Boost.Asio strand + shared_ptr-based async operations
 * for lock-free, high-concurrency port probing.
 */

#ifndef PORTSCANNER_HPP
#define PORTSCANNER_HPP

#include <boost/asio.hpp>
#include <string>
#include <queue>
#include <unordered_map>
#include <iostream>
#include <array>
#include <memory>
#include <cstdint>
#include <cstdio>

// ANSI color codes for terminal output
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_GRAY    "\033[90m"
#define COLOR_RESET   "\033[0m"

using boost::asio::ip::tcp;

/**
 * PortScanner
 *
 * Asynchronous TCP port scanner using Boost.Asio.
 * Probes each port via async_connect; uses a steady_timer to detect
 * filtered ports (firewall drop vs. active RST rejection).
 * Banner grabbing reads initial service responses for fingerprinting.
 */
class PortScanner {
private:
    /// Map of well-known port numbers to service names
    static const std::unordered_map<uint16_t, std::string> knownServices;
    static const uint16_t MAX_PORT = 65535;

    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver{io};
    boost::asio::ip::tcp::endpoint endpoint;

    // Strand serializes callbacks to avoid data races on shared state
    boost::asio::strand<boost::asio::io_context::executor_type> strand{io.get_executor()};

    std::queue<std::uint16_t> portQueue;

    int activeCount    = 0;   ///< Currently in-flight async ops
    int MAX_THREADS    = 0;   ///< Concurrency cap
    int openPorts      = 0;
    int closedPorts    = 0;
    int filteredPorts  = 0;

    std::string      domainName;
    std::uint16_t    startPort  = 1;
    std::uint16_t    endPort    = MAX_PORT;
    std::uint8_t     expiryTime = 2;

    /// Internal: scan next port from queue
    void scan();

    /// Fill the port queue from startPort..endPort
    void setupQueue();

    /// Parse "N" or "N-M" port string into startPort/endPort
    void parsePort(std::string& port);

public:
    /// Construct with all options set immediately
    PortScanner(std::string& ipAddress, std::string& port,
                int maxThreads, std::uint8_t expiry);

    /// Default constructor (use set_options before start/run)
    PortScanner() {}
    ~PortScanner() = default;

    // Configuration setters
    void set_options(std::string& domain, std::string& port,
                     int maxThreads, std::uint8_t expiry);
    void set_max_port(std::uint16_t port);
    void set_max_threads(int value);
    void set_ip_address(std::string ip);
    void set_expiry_time(std::uint8_t value);

    /// Post initial batch of scan() coroutines to the strand
    void start();

    /// Block until all async ops complete; then print summary
    void run();
};

#endif // PORTSCANNER_HPP
