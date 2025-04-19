// compressor.cpp
#include "compressor.h"
#include <fstream>
#include <iostream>

static void flushRun(char byte, size_t runLen, std::ostream& out, size_t minRun) {
    if (runLen > minRun) {
        // compressed form: value, then (runLen - minRun)
        out.put(byte);
        out.put(static_cast<char>(runLen - minRun));
    }
    else {
        // literal form: just dump it runLen times
        for (size_t i = 0; i < runLen; ++i) {
            out.put(byte);
        }
    }
}

void Compressor::RLE(const std::string& inPath, const std::string& outPath) {
    constexpr size_t MIN_RUN = 2; // same as before

    std::ifstream in(inPath, std::ios::binary);
    if (!in) {
        std::cerr << "err opening " << inPath << "\n";
        return;
    }

    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        std::cerr << "err opening " << outPath << "\n";
        return;
    }

    char prev;
    if (!in.get(prev))
        return; // empty file → nothing to do

    size_t runLen = 1;
    char curr;
    while (in.get(curr)) {
        if (curr == prev) {
            ++runLen;
            if (runLen == 255 + MIN_RUN) { flushRun(prev, runLen, out, MIN_RUN); runLen = 0; }
        }
        else {
            flushRun(prev, runLen, out, MIN_RUN);
            prev = curr;
            runLen = 1;
        }
    }

    // flush leftover
    flushRun(prev, runLen, out, MIN_RUN);
}