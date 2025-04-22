#ifndef STORAGE_FORMAT_H
#define STORAGE_FORMAT_H

#include <cstdint>
#include <vector>
#include <chrono> // For timestamps
#include <iosfwd> // Forward declarations for istream/ostream

// Example: Structure to hold information that might be unique
// per packet or group of packets after common headers are stripped.
// Adjust fields based on what Mahir's process preserves.
struct PacketMetadata {
    uint64_t timestamp_ns;      // Original packet timestamp (nanoseconds since epoch, perhaps)
    uint32_t original_length;   // Original length of the packet data (payload)
    // Add other essential unique fields here, e.g.:
    // uint32_t sequence_number;
    // uint16_t source_port; // If relevant and changes
};

// Structure representing a single packet's payload in storage
// This might be simplified if metadata is stored separately or per block
struct StoredPacket {
    PacketMetadata metadata;
    std::vector<uint8_t> payload; // The actual packet payload data
};

// --- Functions for writing/reading this format would go here ---
// Writes a single StoredPacket to a binary output stream.
// Returns true on success, false on failure.
bool write_packet(std::ostream& out, const StoredPacket& packet);

// Reads a single StoredPacket from a binary input stream.
// Returns true on success, false on failure (e.g., EOF or read error).
bool read_packet(std::istream& in, StoredPacket& packet);


#endif // STORAGE_FORMAT_H