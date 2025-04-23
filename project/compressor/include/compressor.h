#ifndef COMPRESSOR_H
#define COMPRESSOR_H
using namespace std;
#include <string>
#include <vector>
#include <cstdint>


class Compressor {
    public:
        // Compressor();
        // ~Compressor();
        void RLE(const std::string& inPath, const std::string& outPath);
        void timeDelta(const std::string& inPath, const std::string& outPath);
        void timeDeltaWithHdr(const std::string& inPath, const std::string& outPath);
        


    private:
        void writeLEB128(int64_t delta, std::vector<uint8_t>& out);
        const uint8_t* readLEB128(const uint8_t* p, int64_t& deltaOut);
        
        // void compress();
};




#endif