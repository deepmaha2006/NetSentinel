/**
 * NetSentinel - Asynchronous TCP Port Scanner
 * Author: deepmaha2006
 * Based on: simple-port-scanner concepts (C++ / Boost.Asio)
 *
 * A high-concurrency TCP port scanner that uses async I/O to probe
 * target hosts for open, closed, and filtered ports. Includes
 * banner grabbing for service fingerprinting.
 *
 * Usage:
 *   ./NetSentinel -i <host> -p <port-range> -t <threads> -e <timeout>
 *
 * Example:
 *   ./NetSentinel -i 127.0.0.1 -p 1-1024 -t 100 -e 2
 *   ./NetSentinel -i scanme.nmap.org -p 80,443,8080 -t 50 -e 3
 */

#include "src/PortScanner.hpp"
#include <boost/program_options.hpp>
#include <iostream>

namespace po = boost::program_options;

void print_banner() {
    std::cout << "\033[36m" << R"(
 _   _      _   ____            _   _            _
| \ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
|  \| |/ _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
| |\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
|_| \_|\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|
)" << "\033[0m";
    std::cout << "\033[90m  Async TCP Port Scanner | C++20 + Boost.Asio\033[0m\n";
    std::cout << "\033[90m  Scan only systems you own or have explicit permission to test.\033[0m\n\n";
}

int main(int argc, char* argv[]) {

    po::options_description desc("Options");
    desc.add_options()
        ("help,h",    "Show this help message")
        ("dname,i",   po::value<std::string>()->default_value("127.0.0.1"),
                      "Target IP address or domain name")
        ("ports,p",   po::value<std::string>()->default_value("1-1024"),
                      "Port range (e.g. 1-1024) or single limit (e.g. 443)")
        ("threads,t", po::value<int>()->default_value(100),
                      "Max concurrent connection threads")
        ("expiry_time,e", po::value<uint8_t>()->default_value(2)->value_name("sec"),
                      "Connection timeout in seconds (filtered detection)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "\033[31m[ERROR]\033[0m " << e.what() << "\n\n";
        std::cout << desc << "\n";
        return 1;
    }

    if (vm.count("help") || argc == 1) {
        print_banner();
        std::cout << desc << "\n";
        std::cout << "Examples:\n"
                  << "  Scan localhost common ports:\n"
                  << "    ./NetSentinel -i 127.0.0.1 -p 1-1024\n\n"
                  << "  Full port scan with more threads:\n"
                  << "    ./NetSentinel -i 192.168.1.1 -p 1-65535 -t 200\n\n"
                  << "  Scan specific ports with longer timeout:\n"
                  << "    ./NetSentinel -i example.com -p 80-443 -e 5\n\n"
                  << "  Test with nmap's demo host:\n"
                  << "    ./NetSentinel -i scanme.nmap.org -p 1-1024 -t 50 -e 3\n\n";
        return 0;
    }

    print_banner();

    std::string ip          = vm["dname"].as<std::string>();
    std::string port        = vm["ports"].as<std::string>();
    int         threads     = vm["threads"].as<int>();
    uint8_t     expiry_time = vm["expiry_time"].as<uint8_t>();

    std::cout << "\033[33m[*]\033[0m Target   : " << ip << "\n";
    std::cout << "\033[33m[*]\033[0m Ports     : " << port << "\n";
    std::cout << "\033[33m[*]\033[0m Threads   : " << threads << "\n";
    std::cout << "\033[33m[*]\033[0m Timeout   : " << (int)expiry_time << "s\n\n";

    try {
        PortScanner scanner;
        scanner.set_options(ip, port, threads, expiry_time);
        scanner.start();
        scanner.run();
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[ERROR]\033[0m " << e.what() << "\n";
        return 1;
    }

    return 0;
}
