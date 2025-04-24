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

int main() { return 0; }