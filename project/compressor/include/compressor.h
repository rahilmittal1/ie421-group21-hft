#ifndef COMPRESSOR_H
#define COMPRESSOR_H
using namespace std;
#include <string>
#include <vector>

// g++ -std=c++17 -Iinclude src/compressor.cpp src/decompressor.cpp  tests/compression_tests.cpp -o compression_tests
// ./compression_tests
class Compressor {
    public:
        // Compressor();
        // ~Compressor();
        void RLE(const std::string& inPath, const std::string& outPath);
        void timeDelta(const std::string& inPath, const std::string& outPath);
        void removeRepetitiveHeaders(const std::string& inPath, const std::string& outPath);
        void huffmanLosslessCompression(const std::string& inPath, const std::string& outPath);


    private:
        void writeLEB128(int64_t delta, std::vector<uint8_t>& out);
        const uint8_t* readLEB128(const uint8_t* p, int64_t& deltaOut);
        bool isEquivalentHeader(const std::vector<char>& a, const std::vector<char>& b);
        // void compress();
};


#endif