#include "decompressor.h"
#include <fstream>
#include <iostream>
#include <string>

/**
    Reverse of the simple RLE that emits: literal ≤2 copies as-is,
    runs >2 as [value][count - 2].
*/
void Decompressor::RLEDecompress(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream in(inputFile, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "error opening compressed file: " << inputFile << std::endl;
        return;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "error opening output file: " << outputFile << std::endl;
        return;
    }

    constexpr size_t MIN_RUN = 2;
    char byte;

    while (in.get(byte)) {
        int next = in.peek();
        if (next == EOF) {
            // Last byte
            out.put(byte);
            break;
        }

        unsigned char offset = static_cast<unsigned char>(next);
        if (offset > 0) {
            // It's a run: consume offset and expand
            in.get();  // consume the offset byte
            size_t runLength = offset + MIN_RUN;
            for (size_t i = 0; i < runLength; ++i) {
                out.put(byte);
            }
        } else {
            // Literal byte, just output it
            out.put(byte);
        }
    }

    in.close();
    out.close();
}
