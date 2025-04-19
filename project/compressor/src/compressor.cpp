#include "compressor.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>

void Compressor::RLE(const std::string& inPath, const std::string& outPath) {
    std::ifstream in(inPath,  std::ios::binary);
    std::ofstream out(outPath, std::ios::binary);
    if (!in || !out) { std::cerr<<"I/O error\n"; return; }

    std::vector<char> literalBuf;
    char prev, curr;
    if (!in.get(prev)) return;

    size_t runLen = 1;
    while (in.get(curr)) {
        if (curr == prev) {
            ++runLen;
            // if a literal buffer is pending, flush it first
            if (!literalBuf.empty()) {
                int c = static_cast<int>(literalBuf.size()) - 1;
                out.put(static_cast<char>(c));
                out.write(literalBuf.data(), literalBuf.size());
                literalBuf.clear();
            }
            // if run too long, break it into chunks of ≤ 128
            if (runLen == 128) {
                out.put(static_cast<char>(1 - 128));
                out.put(prev);
                runLen = 0;
            }
        } else {
            if (runLen > 1) {
                // flush run
                while (runLen > 0) {
                    size_t chunk = std::min(runLen, size_t(128));
                    out.put(static_cast<char>(1 - chunk));
                    out.put(prev);
                    runLen -= chunk;
                }
            } else {
                // single byte → buffer as literal
                literalBuf.push_back(prev);
                if (literalBuf.size() == 128) {
                    int c = static_cast<int>(literalBuf.size()) - 1;
                    out.put(static_cast<char>(c));
                    out.write(literalBuf.data(), literalBuf.size());
                    literalBuf.clear();
                }
            }
            prev = curr;
            runLen = 1;
        }
    }

    // flush remaining run or literal
    if (runLen > 1) {
        while (runLen > 0) {
            size_t chunk = std::min(runLen, size_t(128));
            out.put(static_cast<char>(1 - chunk));
            out.put(prev);
            runLen -= chunk;
        }
    } else {
        literalBuf.push_back(prev);
    }
    if (!literalBuf.empty()) {
        int c = static_cast<int>(literalBuf.size()) - 1;
        out.put(static_cast<char>(c));
        out.write(literalBuf.data(), literalBuf.size());
    }
}
