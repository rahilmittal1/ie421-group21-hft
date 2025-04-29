#include <iostream>
#include <string>
#include <vector>
#include <fstream> // Required for ifstream
#include "parser.h" // Include the parser header

int main(int argc, char* argv[]) {
    std::cout << "Starting PCAP Processor..." << std::endl;

    // --- Configuration from Command Line Arguments ---
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_pcap_file> <output_binary_file>" << std::endl;
        std::cerr << "Example: " << argv[0] << " ../../data/20180127_IEXTP1_DEEP1.0.pcap ../../data/processed_packets.bin" << std::endl;
        return 1; // Indicate error: insufficient arguments
    }

    std::string pcap_input_file = argv[1];
    std::string binary_output_file = argv[2];

    // --- Processing ---
    std::cout << "Processing PCAP file: " << pcap_input_file << std::endl;
    bool success = process_pcap_to_binary(pcap_input_file, binary_output_file);

    if (success) {
        std::cout << "Successfully created binary file: " << binary_output_file << std::endl;
    } else {
        std::cerr << "Failed to process PCAP file." << std::endl;
        return 1; // Indicate error
    }

    // --- Optional: Reading back the data for verification ---
    std::cout << "\nReading back processed data for verification..." << std::endl;
    std::ifstream in_stream(binary_output_file, std::ios::binary);
    if (!in_stream) {
        std::cerr << "Error: Could not open binary file for reading: " << binary_output_file << std::endl;
        return 1;
    }

    ProcessedPacket packet_read;
    int count = 0;
    while (read_packet(in_stream, packet_read)) {
        count++;
        // You can add more detailed printing here if needed
        // std::cout << "Read Packet " << count << ": Timestamp=" << packet_read.timestamp
        //           << ", Seq=" << packet_read.sequence_number
        //           << ", Payload Size=" << packet_read.payload.size() << std::endl;
    }
    in_stream.close();

    if (count > 0) {
         std::cout << "Successfully read back " << count << " processed packets from " << binary_output_file << std::endl;
    } else {
         std::cout << "No packets were read back from " << binary_output_file << " (or file was empty)." << std::endl;
    }


    std::cout << "Processing finished." << std::endl;
    return 0; // Indicate success
}