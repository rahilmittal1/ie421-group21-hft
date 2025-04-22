#include "storage_format.h"
#include <ostream>
#include <istream>
#include <vector>
#include <cstdint>

// Writes a single StoredPacket to a binary output stream.
// Format:
// - PacketMetadata (timestamp_ns, original_length)
// - uint32_t payload_size
// - payload data (payload_size bytes)
bool write_packet(std::ostream& out, const StoredPacket& packet) {
    // Write metadata directly
    out.write(reinterpret_cast<const char*>(&packet.metadata), sizeof(PacketMetadata));
    if (!out) return false; // Check stream state after write

    // Write payload size (as uint32_t)
    uint32_t payload_size = static_cast<uint32_t>(packet.payload.size());
    out.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));
    if (!out) return false; // Check stream state

    // Write payload data only if size > 0
    if (payload_size > 0) {
        out.write(reinterpret_cast<const char*>(packet.payload.data()), payload_size);
        if (!out) return false; // Check stream state
    }

    return true; // Success
}

// Reads a single StoredPacket from a binary input stream.
// Assumes the format written by write_packet.
bool read_packet(std::istream& in, StoredPacket& packet) {
    // Read metadata directly
    in.read(reinterpret_cast<char*>(&packet.metadata), sizeof(PacketMetadata));
    // Check if read was successful (covers EOF and errors)
    // Need to check gcount() because reading exactly 0 bytes at EOF might not set failbit
    if (in.gcount() != sizeof(PacketMetadata)) {
        return false;
    }

    // Read payload size
    uint32_t payload_size = 0;
    in.read(reinterpret_cast<char*>(&payload_size), sizeof(payload_size));
    if (in.gcount() != sizeof(payload_size)) {
         // If we read metadata but failed to read size, it's an error/incomplete packet
        return false;
    }

    // Resize vector and read payload data
    try {
        packet.payload.resize(payload_size);
    } catch (const std::bad_alloc& e) {
        // Handle potential memory allocation failure
        return false;
    }

    if (payload_size > 0) {
        in.read(reinterpret_cast<char*>(packet.payload.data()), payload_size);
        if (in.gcount() != payload_size) {
            // Failed to read the full payload
            return false;
        }
    } else {
        // If payload_size is 0, ensure the vector is empty
        packet.payload.clear();
    }

    // Peek to see if we are at EOF. If we successfully read a 0-payload packet
    // right at the end, the stream state might still be good, but there's nothing more.
    // A successful read followed by peek() == EOF is a valid end condition.
    // However, simply returning true here is correct as we successfully read one packet.
    // The caller loop should handle the next read failure.
    return true; // Success
}