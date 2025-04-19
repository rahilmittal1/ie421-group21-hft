#include "compressor.h"
#include "decompressor.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <cassert>
#include <filesystem>

/**
 * Run a single RLE test: compress, decompress, assert equality, and print sizes.
 */
void testRLE(const std::string& input_path,
             const std::string& compressed_path,
             const std::string& decompressed_path) {
    Compressor compressor;
    Decompressor decompressor;
    // 1) Compress
    compressor.RLE(input_path, compressed_path);
    // 2) Decompress
    decompressor.RLEDecompress(compressed_path, decompressed_path);

    // 3) Report sizes
    auto original_size   = std::filesystem::file_size(input_path);
    auto compressed_size = std::filesystem::file_size(compressed_path);
    std::cout << "[RLE] Original size:   " << original_size   << " bytes\n";
    std::cout << "[RLE] Compressed size: " << compressed_size << " bytes\n";

    // 4) Load file data
    std::ifstream orig_in(input_path, std::ios::binary);
    std::vector<char> orig_data{
        std::istreambuf_iterator<char>(orig_in),
        std::istreambuf_iterator<char>()
    };

    std::ifstream decomp_in(decompressed_path, std::ios::binary);
    std::vector<char> decomp_data{
        std::istreambuf_iterator<char>(decomp_in),
        std::istreambuf_iterator<char>()
    };

    // 5) Validate
    assert(orig_data == decomp_data && "Decompressed data does not match original!");
    std::cout << "[RLE] Validation passed: decompressed data matches original.\n";
}

int main() {
    testRLE(
      "../data/test_small.pcap",
      "../data/test_small.pcap.rle",
      "../data/test_small_decompressed.pcap"
    );
    return 0;
}
