#include "compressor.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>
#include "utils/SimplePcapReader.h"


inline uint64_t zigzag(int64_t v) { return (v << 1) ^ (v >> 63); }
inline int64_t  unzigzag(uint64_t v){ return (v >> 1) ^ -static_cast<int64_t>(v & 1); }

/**
 * Input can be any file type, not specific to PCAP
 */
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

/**
 * Input must be a PCAP file
 */
void Compressor::timeDelta(const std::string& inPath, const std::string& outPath) {
    SimplePcapReader reader(inPath);
    std::ofstream out(outPath, std::ios::binary);
    if (!out) { std::cerr << "Cannot open " << outPath << '\n'; return; }

    PacketView pkt;
    bool first = true;
    uint64_t prevUs = 0;

    std::vector<uint8_t> buf;           // scratch for LEB128
    buf.reserve(16);

    while (reader.readNext(pkt)) {
        uint64_t curUs = pkt.absTs / 1'000ULL;            // <- microseconds
        int64_t  delta = first ? 0 : static_cast<int64_t>(curUs - prevUs);
        prevUs = curUs;

        if (first) {                        // write base timestamp once
            uint64_t base = curUs;
            out.write(reinterpret_cast<char*>(&base), sizeof(base));
            first = false;
        }

        /* ---- delta‑t (VarInt) ---- */
        writeLEB128(delta, buf);
        out.write(reinterpret_cast<char*>(buf.data()), buf.size());
        buf.clear();

        /* ---- captured length (VarInt) ---- */
        writeLEB128(pkt.len, buf);
        out.write(reinterpret_cast<char*>(buf.data()), buf.size());
        buf.clear();

        /* ---- packet bytes ---- */
        out.write(reinterpret_cast<const char*>(pkt.data), pkt.len);
    }
    out.flush();
}



void Compressor::writeLEB128(int64_t delta, std::vector<uint8_t>& out) {
    uint64_t u = zigzag(delta);
    while (u >= 0x80) { out.push_back(static_cast<uint8_t>(u) | 0x80); u >>= 7; }
    out.push_back(static_cast<uint8_t>(u));
}
const uint8_t* Compressor::readLEB128(const uint8_t* p, int64_t& deltaOut) {
    uint64_t result = 0; int shift = 0, byte;
    do {
        byte = *p++; result |= uint64_t(byte & 0x7F) << shift; shift += 7;
    } while (byte & 0x80);
    deltaOut = unzigzag(result);
    return p;
}

