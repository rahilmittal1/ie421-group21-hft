#include "parser.h"
#include <iostream> // For potential error logging
#include <cstring>  // For std::memcpy if needed for fixed-size arrays later

// Helper function to write raw bytes
template<typename T>
bool write_binary(std::ofstream& stream, const T& value) {
    stream.write(reinterpret_cast<const char*>(&value), sizeof(T));
    return stream.good();
}

// Helper function to read raw bytes
template<typename T>
bool read_binary(std::ifstream& stream, T& value) {
    stream.read(reinterpret_cast<char*>(&value), sizeof(T));
    // Check if read succeeded and expected number of bytes were read
    return stream.good() && stream.gcount() == sizeof(T);
}


bool write_packet(std::ofstream& out_stream, const ProcessedPacket& packet) {
    if (!out_stream.is_open() || !out_stream.good()) {
        std::cerr << "Error: Output stream is not ready for writing." << std::endl;
        return false;
    }

    // --- Write Header Fields ---
    // IMPORTANT: Write fields individually to avoid padding issues
    //            and ensure consistent layout across compilers/platforms.
    if (!write_binary(out_stream, packet.timestamp)) return false;
    if (!write_binary(out_stream, packet.sequence_number)) return false;
    // Add writes for other fixed-size header fields here...
    // Example: if (!write_binary(out_stream, packet.message_type)) return false;
    // Example: out_stream.write(packet.symbol, sizeof(packet.symbol)); if (!out_stream.good()) return false;


    // --- Write Payload ---
    // 1. Write the size of the payload
    uint32_t payload_size = static_cast<uint32_t>(packet.payload.size());
    if (!write_binary(out_stream, payload_size)) return false;

    // 2. Write the payload data itself
    if (payload_size > 0) {
        out_stream.write(reinterpret_cast<const char*>(packet.payload.data()), payload_size);
        if (!out_stream.good()) return false;
    }

    return true; // Success
}


bool read_packet(std::ifstream& in_stream, ProcessedPacket& packet) {
    if (!in_stream.is_open() || !in_stream.good()) {
        // Don't print error for EOF, just return false
        // std::cerr << "Error: Input stream is not ready for reading." << std::endl;
        return false;
    }

    // Check if we are at EOF before attempting to read
    if (in_stream.peek() == EOF) {
        return false;
    }

    // --- Read Header Fields ---
    if (!read_binary(in_stream, packet.timestamp)) return false;
    if (!read_binary(in_stream, packet.sequence_number)) return false;
    // Add reads for other fixed-size header fields here...
    // Example: if (!read_binary(in_stream, packet.message_type)) return false;
    // Example: in_stream.read(packet.symbol, sizeof(packet.symbol)); if (!in_stream.good() || in_stream.gcount() != sizeof(packet.symbol)) return false;


    // --- Read Payload ---
    // 1. Read the size of the payload
    uint32_t payload_size = 0;
    if (!read_binary(in_stream, payload_size)) {
         // Check if the failure was due to EOF after reading headers but before size
        if (in_stream.eof() && in_stream.gcount() == 0) return false;
        // Otherwise it's an error
        std::cerr << "Error reading payload size." << std::endl;
        return false;
    }


    // 2. Read the payload data itself
    packet.payload.resize(payload_size); // Resize vector to hold the data
    if (payload_size > 0) {
        in_stream.read(reinterpret_cast<char*>(packet.payload.data()), payload_size);
        if (!in_stream.good() || static_cast<size_t>(in_stream.gcount()) != payload_size) {
             // Check if the failure was due to EOF during payload read
            if (in_stream.eof()) return false;
            // Otherwise it's an error
            std::cerr << "Error reading payload data. Expected " << payload_size << " bytes, got " << in_stream.gcount() << std::endl;
            return false;
        }
    }

    return true; // Success
}