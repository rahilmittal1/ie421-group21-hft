#include <iostream>
#include <fstream>
#include <string>
#include "parser.h"
#include <pcap.h>

#include <pcap.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


struct Packet{
    
};

void do_some() {
    // char file_name[] = "project/data/example.pcap";
    char file_name[] = "/Users/mahir/Desktop/IE421/project/data/example.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* fp = pcap_open_offline(file_name, errbuf);
    if (fp == nullptr) {
        std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;

    while ((result = pcap_next_ex(fp, &header, &packet)) >= 0) {
        if (result == 0) continue;

        // Parse Timestamp
        std::cout << "The timestamp is " << header->ts.tv_sec << std::endl;

        // Parse Ethernet
        const struct ether_header* eth = (struct ether_header*)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
            std::cout << "Non-IP packet, skipping.\n";
            continue;
        }

        // Parse IP header
        const struct ip* iphdr = (struct ip*)(packet + sizeof(struct ether_header));
        if (iphdr->ip_p != IPPROTO_UDP) {
            std::cout << "Non-UDP packet, skipping.\n";
            continue;
        }

        // Parse UDP header
        int ip_header_len = iphdr->ip_hl * 4;
        const struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);

        // Print header info
        std::cout << "From " << inet_ntoa(iphdr->ip_src)
                  << " to " << inet_ntoa(iphdr->ip_dst) << "\n";
        std::cout << "UDP Src Port: " << ntohs(udph->uh_sport)
                  << ", Dst Port: " << ntohs(udph->uh_dport)
                  << ", Length: " << ntohs(udph->uh_ulen) << "\n";

        // const u_char* payload = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
        const u_char* payload = packet + 42;
        int payload_len = ntohs(udph->uh_ulen) - sizeof(struct udphdr);

        // Print first 16 bytes of payload as hex
        std::cout << "Payload: ";
        for (int i = 0; i < payload_len; ++i)
            printf("%02x ", payload[i]);
        std::cout << "\n";
        std::cout << std::endl;

        const uint8_t* msg = payload + 11;
        // const uint8_t* msg = payload + 2;
        std::cout << "Raw message_type byte: 0x" << std::hex << (int)msg[0] << std::dec << std::endl;
        char message_type = msg[0]; // first byte = type
        std::cout << "message_type is " << message_type << std::endl;
        if (message_type == 'D') {
            uint8_t flags = msg[1];
        
            uint64_t timestamp = ((uint64_t)ntohl(*(uint32_t*)(msg + 2)) << 32) |
                                  ntohl(*(uint32_t*)(msg + 6));
        
            char symbol[9];
            memcpy(symbol, msg + 10, 8);
            symbol[8] = '\0';
            std::string symbol_str(symbol);

            std::cout << "  Raw Symbol Bytes: ";
            for (int i = 0; i < 8; i++) {
                printf("%02x ", msg[10 + i]);
            }
            std::cout << std::endl;
        
            uint32_t round_lot = ntohl(*(uint32_t*)(msg + 18));
        
            uint64_t raw_price = ((uint64_t)ntohl(*(uint32_t*)(msg + 22)) << 32) |
                                  ntohl(*(uint32_t*)(msg + 26));
            double price = raw_price / 10000.0;
        
            uint8_t luld_tier = msg[30];
        
            std::cout << "SECURITY DIRECTORY MESSAGE\n";
            std::cout << "  Symbol: " << symbol_str << "\n";
            std::cout << "  Timestamp: " << timestamp << "\n";
            std::cout << "  Round Lot Size: " << round_lot << "\n";
            std::cout << "  Adjusted POC Price: $" << price << "\n";
            std::cout << "  LULD Tier: " << (int)luld_tier << "\n";
        }
    }

    pcap_close(fp);
}


// void do_some_2() {
//     char file_name[] = "/Users/mahir/Desktop/IE421/project/data/example.pcap";
//     char errbuf[PCAP_ERRBUF_SIZE];

//     pcap_t* fp = pcap_open_offline(file_name, errbuf);
//     if (fp == nullptr) {
//         std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
//         return;
//     }

//     struct pcap_pkthdr* header;
//     const u_char* packet;
//     int result;

//     while ((result = pcap_next_ex(fp, &header, &packet)) >= 0) {
//         if (result == 0) continue; 

//         std::cout << packet;

//         const u_char* payload = packet + 42;
//         const u_char* symbol = packet + 52;

//         std::cout << "Payload: ";
//         for (int i = 0; i < 100; ++i)
//             printf("%02x ", payload[i]);
//         std::cout << "\n";
//         std::cout << std::endl;

//         std::cout << "symbol ";
//         for (int i = 0; i < 8; ++i)
//             printf("%02x ", symbol[i]);
//         std::cout << "\n";
    
//     }
// }


/// Extracts just the UDP‐payload (after Ethernet/IP/UDP headers) from each packet
/// in `pcap_path` and appends it to `out_bin_path`.
void extractPayload(const std::string& pcap_path,
                    const std::string& out_bin_path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_path.c_str(), errbuf);
    if (!handle) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return;
    }

    bool skipIEXTransportHeader = true;
    size_t transportHeaderLen = 10; 

    std::ofstream out(out_bin_path, std::ios::binary|std::ios::app);
    if (!out.is_open()) {
        std::cerr << "Failed to open output file: " << out_bin_path << "\n";
        pcap_close(handle);
        return;
    }

    struct pcap_pkthdr* hdr;
    const u_char* pkt;
    while (pcap_next_ex(handle, &hdr, &pkt) == 1) {
        // 1) Ethernet
        if (hdr->caplen < sizeof(ether_header)) continue;
        auto eth = (const ether_header*)pkt;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

        // 2) IP
        const u_char* ip_start = pkt + sizeof(ether_header);
        auto iphdr = (const ip*)ip_start;
        if (iphdr->ip_p != IPPROTO_UDP) continue;
        size_t ip_hdr_len = iphdr->ip_hl * 4;

        // 3) UDP
        const u_char* udp_start = ip_start + ip_hdr_len;
        if (hdr->caplen < (udp_start - pkt) + sizeof(udphdr)) continue;
        auto udph = (const udphdr*)udp_start;
        size_t udp_len = ntohs(udph->uh_ulen);

        // 4) Compute payload bounds
        size_t payload_offset = sizeof(ether_header)
                              + ip_hdr_len
                              + sizeof(udphdr)
                              + (skipIEXTransportHeader ? transportHeaderLen : 0);
        size_t payload_len = (udp_len > sizeof(udphdr) + (skipIEXTransportHeader?transportHeaderLen:0))
                           ? udp_len - sizeof(udphdr) - (skipIEXTransportHeader?transportHeaderLen:0)
                           : 0;
        if (payload_len == 0 || hdr->caplen < payload_offset + payload_len)
            continue;

        // 5) Write raw payload bytes
        out.write(reinterpret_cast<const char*>(pkt + payload_offset),
                  std::streamsize(payload_len));
    }

    out.close();
    pcap_close(handle);
}

static constexpr size_t IEX_TRANSPORT_HDR_LEN = 10;

// Holds measured header lengths
struct HeaderSizes {
    size_t eth;  // Ethernet
    size_t ip;   // IPv4
    size_t udp;  // UDP
    size_t iex;  // IEX framing
};

// Measure the four header lengths for a single raw packet buffer
HeaderSizes measure_headers(const u_char* pkt) {
    HeaderSizes hs;
    hs.eth = sizeof(struct ether_header);

    // IP header length is in the low 4 bits of ip_hl, times 4
    auto iphdr = reinterpret_cast<const struct ip*>(pkt + hs.eth);
    hs.ip = iphdr->ip_hl * 4;

    hs.udp = sizeof(struct udphdr);
    hs.iex = IEX_TRANSPORT_HDR_LEN;
    return hs;
}

/// Open a pcap file, iterate packets, and print header sizes
void print_header_sizes(const std::string& pcap_path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_path.c_str(), errbuf);
    if (!handle) {
        std::cerr << "ERROR: pcap_open_offline failed: " << errbuf << "\n";
        return;
    }

    struct pcap_pkthdr* hdr;
    const u_char* pkt;
    int res;
    while ((res = pcap_next_ex(handle, &hdr, &pkt)) == 1) {
        // strip out non-IPv4 or non-UDP early if you like—but here we’ll always measure
        auto hs = measure_headers(pkt);
        std::cout
            << "Packet captured at " << hdr->ts.tv_sec << "." << hdr->ts.tv_usec << "\n"
            << "  Ethernet header: " << hs.eth << " bytes\n"
            << "  IP      header: " << hs.ip  << " bytes\n"
            << "  UDP     header: " << hs.udp << " bytes\n"
            << "  IEX     header: " << hs.iex << " bytes\n"
            << "  => total overhead: "
               << (hs.eth + hs.ip + hs.udp + hs.iex)
            << " bytes\n\n";
    }

    pcap_close(handle);
}

// int main() { return 0; }

#include <iostream>
#include <iomanip>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

constexpr size_t IEX_TRANSPORT_HEADER_LEN = 40;

void strip_and_parse() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char file_name[] = "/Users/mahir/Desktop/IE421/project/data/example.pcap";
    pcap_t* handle = pcap_open_offline(file_name, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return;
    }

    pcap_pkthdr* hdr;
    const u_char* pkt;
    while (pcap_next_ex(handle, &hdr, &pkt) == 1) {
        std::cout << "Captured: " << hdr->caplen 
              << " bytes, Original on-wire: " << hdr->len << " bytes\n";
        size_t offset = 0;

        // 1) Ethernet
        constexpr size_t ETH_HDR_LEN = sizeof(ether_header);
        if (hdr->caplen < ETH_HDR_LEN) continue;
        auto *eth = reinterpret_cast<const ether_header*>(pkt);
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;
        offset += ETH_HDR_LEN;

        // 2) IP
        if (hdr->caplen < offset + sizeof(ip)) continue;
        auto *ip4 = reinterpret_cast<const ip*>(pkt + offset);
        if (ip4->ip_p != IPPROTO_UDP) continue;
        size_t ip_hdr_len = (ip4->ip_hl & 0x0F) * 4;
        offset += ip_hdr_len;

        // 3) UDP
        if (hdr->caplen < offset + sizeof(udphdr)) continue;
        auto *udp = reinterpret_cast<const udphdr*>(pkt + offset);
        size_t udp_len = ntohs(udp->uh_ulen);
        offset += sizeof(udphdr);

        // Print header sizes
        std::cout << "Ethernet header: " << ETH_HDR_LEN << " bytes, "
                  << "IP header: "      << ip_hdr_len   << " bytes, "
                  << "UDP header: "     << sizeof(udphdr) 
                  << " bytes\n";

        // 4) UDP Payload
        if (hdr->caplen < offset) continue;
        size_t udp_payload_len = hdr->caplen - offset;
        std::cout << "Raw UDP payload length: " << udp_payload_len << " bytes\n";

        // 5) Skip IEX transport header
        if (udp_payload_len <= IEX_TRANSPORT_HEADER_LEN) continue;
        offset += IEX_TRANSPORT_HEADER_LEN;
        size_t deep_payload_len = udp_payload_len - IEX_TRANSPORT_HEADER_LEN;
        std::cout << "After skipping IEX transport header (" 
                  << IEX_TRANSPORT_HEADER_LEN << " bytes): "
                  << deep_payload_len << " bytes\n";

        const u_char* payload = pkt + offset;

        // 6) Parse DEEP messages (length-prefixed)
        size_t pos = 0;
        while (pos + 4 <= deep_payload_len) {
            // 2-byte big-endian message length
            uint16_t msg_len = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
            if (msg_len < 4 || pos + msg_len > deep_payload_len) break;

            uint8_t msg_type = *(payload + pos + 2);
            uint8_t flags    = *(payload + pos + 3);

            std::cout << " ▶ DEEP message: length=" << msg_len
                      << ", type=0x" << std::hex << std::setw(2) << std::setfill('0')
                      << (int)msg_type << std::dec
                      << ", flags=0x" << std::hex << std::setw(2) << (int)flags 
                      << std::dec << "\n";

            // e.g. if you want to dump the type as a character when printable:
            if (msg_type >= 0x20 && msg_type <= 0x7E) {
                std::cout << "    as char: '" << static_cast<char>(msg_type) << "'\n";
            }

            // Advance to next message
            pos += msg_len;
        }

        std::cout << "----------------------------------------\n";
    }

    pcap_close(handle);
}

#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

void parse_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char fname[] = "/Users/mahir/Desktop/IE421/project/data/example.pcap";
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return;
    }

    pcap_pkthdr* hdr;
    const u_char* pkt;
    while (pcap_next_ex(handle, &hdr, &pkt) == 1) {
        std::cout << "Captured: " << hdr->caplen << " \n";  // CAP Len TOTAL
        std::cout << "length " << hdr->len << "bytes" << std::endl;

        // caplen is total length of everything captured. len is length of packet

        // 1) Ethernet
        constexpr size_t ETH_HDR_LEN = sizeof(ether_header);
        if (hdr->caplen < ETH_HDR_LEN) continue;
        auto *eth = reinterpret_cast<const ether_header*>(pkt);
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

        // 2) IPv4
        size_t ip_offset = ETH_HDR_LEN;
        if (hdr->caplen < ip_offset + sizeof(ip)) continue;
        auto *ip4 = reinterpret_cast<const ip*>(pkt + ip_offset);
        if (ip4->ip_p != IPPROTO_UDP) continue;
        size_t ip_hdr_len = (ip4->ip_hl & 0x0F) * 4;

        // 3) UDP
        size_t udp_offset = ip_offset + ip_hdr_len;
        if (hdr->caplen < udp_offset + sizeof(udphdr)) continue;
        auto *udp = reinterpret_cast<const udphdr*>(pkt + udp_offset);
        size_t udp_hdr_len = sizeof(udphdr);
        uint16_t udp_len = ntohs(udp->uh_ulen);

        // 4) UDP payload
        size_t payload_offset = udp_offset + udp_hdr_len;
        // sanity-check caplen vs length field
        size_t payload_len = 0;
        if (udp_len > udp_hdr_len) {
            payload_len = udp_len - udp_hdr_len;
            if (hdr->caplen < payload_offset + payload_len)
                payload_len = hdr->caplen - payload_offset;
        }

        // Print header sizes
        std::cout
            << "Ethernet header: " << ETH_HDR_LEN << " bytes, "
            << "IP header: "      << ip_hdr_len   << " bytes, "
            << "UDP header: "     << udp_hdr_len  << " bytes\n"
            << "UDP payload length: " << payload_len << " bytes\n";

        const u_char* payload = pkt + payload_offset;

        // 5) Parse DEEP messages by their own length prefix
        size_t pos = 0;
        while (pos + 2 <= payload_len) {
            // 2-byte big-endian length
            uint16_t msg_len = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
            if (msg_len < 4 || pos + msg_len > payload_len) break;

            uint8_t msg_type = *(payload + pos + 2);
            uint8_t flags    = *(payload + pos + 3);

            std::cout
                << "  DEEP msg: len=" << msg_len
                << ", type=0x" << std::hex << std::setw(2) << std::setfill('0') << (int)msg_type
                << std::dec
                << ", flags=0x" << std::hex << std::setw(2) << (int)flags << std::dec
                << "\n";

            pos += msg_len;
        }

        std::cout << "----------------------------------------\n";
    }

    pcap_close(handle);
}



// for (unsinged int i = 0; )