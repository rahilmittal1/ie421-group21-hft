#ifndef PARSER_H
#define PARSER_H

#include <vector>
#include <cstdint>
#include <fstream>
#include <string> // Include for std::string

// NOTE: Adjust this structure based on the actual header fields
// remaining after Mahir's processing removes redundant parts.
struct ProcessedPacket {
    uint64_t timestamp;       // Example: IEX timestamp
    uint32_t sequence_number; // Example: Packet sequence number
    // Add other essential non-redundant header fields here...
    // For example: uint16_t message_type; char symbol[8];

    std::vector<uint8_t> payload; // The actual message payload
};

// Function to write a single processed packet to a binary file stream
// Returns true on success, false on failure
bool write_packet(std::ofstream& out_stream, const ProcessedPacket& packet);

// Function to read a single processed packet from a binary file stream
// Returns true on success, false on failure (e.g., EOF or read error)
bool read_packet(std::ifstream& in_stream, ProcessedPacket& packet);


#endif // PARSER_H