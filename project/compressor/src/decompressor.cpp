#include "decompressor.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>

void Decompressor::RLEDecompress(const std::string& inPath,
                                 const std::string& outPath) {
    std::ifstream in(inPath,  std::ios::binary);
    std::ofstream out(outPath, std::ios::binary);
    if (!in || !out) { std::cerr<<"I/O error\n"; return; }

    while (true) {
        int ic = in.get();
        if (ic == EOF) break;
        int8_t c = static_cast<int8_t>(ic);
        if (c >= 0) {
            // literal block of length c+1
            std::vector<char> buf(c + 1);
            in.read(buf.data(), c + 1);
            out.write(buf.data(), c + 1);
        } else if (c != -128) {
            // run block of length 1-c
            char value = in.get();
            size_t runLen = static_cast<size_t>(1 - c);
            for (size_t i = 0; i < runLen; ++i)
                out.put(value);
        }
    }
}
