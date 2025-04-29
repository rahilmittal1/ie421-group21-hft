#include "parser.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <netinet/if_ether.h> // For ether_header
#include <netinet/ip.h>       // For ip header
#include <netinet/udp.h>      // For udphdr
#include <arpa/inet.h>        // For ntohs, ntohl
#include <iomanip>            // For std::hex, std::setw, std::setfill

// Function to write a single ProcessedPacket to the binary file
bool write_packet(std::ofstream& out_stream, const ProcessedPacket& packet) {
    // Write timestamp (uint64_t)
    out_stream.write(reinterpret_cast<const char*>(&packet.timestamp), sizeof(packet.timestamp));
    // Write sequence number (uint64_t)
    out_stream.write(reinterpret_cast<const char*>(&packet.sequence_number), sizeof(packet.sequence_number));
    // Write payload size (size_t, assuming 64-bit size_t for consistency)
    uint64_t payload_size = packet.payload.size();
    out_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));
    // Write payload data - Cast to const char*
    out_stream.write(reinterpret_cast<const char*>(packet.payload.data()), payload_size);
    return out_stream.good();
}

// Function to read a single ProcessedPacket from the binary file
bool read_packet(std::ifstream& in_stream, ProcessedPacket& packet) {
    // Read timestamp
    in_stream.read(reinterpret_cast<char*>(&packet.timestamp), sizeof(packet.timestamp));
    if (!in_stream) return false; // Check for read errors or EOF
    // Read sequence number
    in_stream.read(reinterpret_cast<char*>(&packet.sequence_number), sizeof(packet.sequence_number));
     if (!in_stream) return false;
    // Read payload size
    uint64_t payload_size;
    in_stream.read(reinterpret_cast<char*>(&payload_size), sizeof(payload_size));
     if (!in_stream) return false;
    // Resize payload vector and read data - Cast to char*
    packet.payload.resize(payload_size);
    in_stream.read(reinterpret_cast<char*>(packet.payload.data()), payload_size);
    return in_stream.good();
}


// Main processing function
bool process_pcap_to_binary(const std::string& pcap_input_path, const std::string& binary_output_path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_input_path.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Error: pcap_open_offline failed for " << pcap_input_path << ": " << errbuf << std::endl;
        return false;
    }

    std::ofstream out_stream(binary_output_path, std::ios::binary | std::ios::trunc);
    if (!out_stream) {
        std::cerr << "Error: Could not open binary output file: " << binary_output_path << std::endl;
        pcap_close(handle);
        return false;
    }

    pcap_pkthdr* hdr;
    const u_char* pkt;
    uint64_t packet_sequence = 0; // Initialize sequence number
    int pcap_packet_count = 0; // Counter for packets read from pcap
    int processed_message_count = 0; // Counter for messages actually processed

    // --- Main Packet Processing Loop ---
    while (pcap_next_ex(handle, &hdr, &pkt) == 1) {
        pcap_packet_count++;
        size_t offset = 0;

        // 1) Ethernet Header
        constexpr size_t ETH_HDR_LEN = sizeof(ether_header);
        if (hdr->caplen < ETH_HDR_LEN) continue;
        auto *eth = reinterpret_cast<const ether_header*>(pkt);
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue; // Only process IPv4 packets
        offset += ETH_HDR_LEN;

        // 2) IP Header
        if (hdr->caplen < offset + sizeof(ip)) continue;
        auto *ip4 = reinterpret_cast<const ip*>(pkt + offset);
        if (ip4->ip_p != IPPROTO_UDP) continue; // Only process UDP packets
        size_t ip_hdr_len = (ip4->ip_hl & 0x0F) * 4; // Calculate actual IP header length
        if (hdr->caplen < offset + ip_hdr_len) continue; // Ensure captured length covers IP header
        offset += ip_hdr_len;

        // 3) UDP Header
        if (hdr->caplen < offset + sizeof(udphdr)) continue;
        // auto *udp = reinterpret_cast<const udphdr*>(pkt + offset); // udp variable not used currently
        size_t udp_hdr_len = sizeof(udphdr);
        offset += udp_hdr_len;

        // --- IEX DEEP Payload Processing ---
        if (hdr->caplen <= offset) continue; // Check if there's any UDP payload
        const u_char* udp_payload_start = pkt + offset;
        size_t udp_payload_len = hdr->caplen - offset;

        // --- Skip IEX TP Header (DEEP 1.0 usually has this) ---
        constexpr size_t IEX_TRANSPORT_HEADER_LEN = 8; // Keep skipping the 8-byte TP header
        const u_char* deep_payload_start = udp_payload_start;
        size_t deep_payload_len = udp_payload_len;

        if (IEX_TRANSPORT_HEADER_LEN > 0) {
            if (deep_payload_len <= IEX_TRANSPORT_HEADER_LEN) {
                continue;
            }
            deep_payload_start += IEX_TRANSPORT_HEADER_LEN;
            deep_payload_len -= IEX_TRANSPORT_HEADER_LEN;
        }
        // --- End Skipping Header ---

        // --- Remove or comment out all previous debug blocks ---

        // --- Loop through DEEP messages within the UDP payload ---
        size_t pos = 0;
        bool first_message_found = false; // Flag to track if we found the start
        while (pos + 2 <= deep_payload_len) { // Need at least 2 bytes for length field

            // Read potential message length
            uint16_t msg_len = ntohs(*reinterpret_cast<const uint16_t*>(deep_payload_start + pos));

            // --- Validation Logic ---
            // Smallest IEX DEEP msg is System Event 'S' (9 bytes)
            // Largest is Add Order - No Max Size (48 bytes + symbol len) - use a reasonable upper bound?
            // Or just check against remaining payload length.
            constexpr uint16_t MIN_DEEP_MSG_LEN = 9;
            bool is_valid_len = (msg_len >= MIN_DEEP_MSG_LEN && pos + msg_len <= deep_payload_len);

            // Optional: Add a check for known message types if needed for stricter validation
            // unsigned char msg_type = *(deep_payload_start + pos + 2);
            // bool is_valid_type = (msg_type == 'S' || msg_type == 'H' || ...);

            if (is_valid_len /* && is_valid_type */) {
                // Found a potentially valid message
                first_message_found = true;

                // --- Create and Write ProcessedPacket ---
                ProcessedPacket processed_packet;
                processed_packet.timestamp = static_cast<uint64_t>(hdr->ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(hdr->ts.tv_usec) * 1000ULL;
                processed_packet.sequence_number = packet_sequence++;
                processed_packet.payload.assign(deep_payload_start + pos, deep_payload_start + pos + msg_len);

                if (!write_packet(out_stream, processed_packet)) {
                    std::cerr << "Error: Failed to write processed packet to " << binary_output_path << std::endl;
                    pcap_close(handle);
                    out_stream.close();
                    return false;
                }
                processed_message_count++;

                // Advance to the next message
                pos += msg_len;

            } else {
                // Invalid length or doesn't fit
                if (first_message_found) {
                    // If we were already processing messages, an invalid length means the end of messages in this payload
                    // Or potentially data corruption. Log a warning?
                    // std::cerr << "Warning: Encountered invalid message length/structure after finding valid messages. UDP Packet #" << pcap_packet_count << ", Pos: " << pos << std::endl;
                    break; // Stop processing this UDP payload
                } else {
                    // Haven't found the first message yet, advance position by 1 byte to keep searching
                    pos++;
                }
            }
        } // End while loop for messages in UDP payload
    } // End while pcap_next_ex

    // Check for errors after the loop
    int pcap_stat = pcap_next_ex(handle, &hdr, &pkt);
    if (pcap_stat == -1) {
        std::cerr << "Error reading packets from " << pcap_input_path << ": " << pcap_geterr(handle) << std::endl;
        // Decide if this is a fatal error or just end of processing
    }

    pcap_close(handle);
    out_stream.close();

    // Final summary message (ensure this is reached)
    std::cout << "Successfully processed " << pcap_input_path << " (read " << pcap_packet_count << " pcap packets)"
              << " and wrote " << processed_message_count << " messages to binary data file " << binary_output_path << std::endl;
    return true;
}


/* // Keep the old function commented out
void strip_and_parse() {
    // ... old implementation ...
}
*/