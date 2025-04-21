#include "decompressor.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>


inline uint64_t zigzag(int64_t v) { return (v << 1) ^ (v >> 63); }
inline int64_t  unzigzag(uint64_t v){ return (v >> 1) ^ -static_cast<int64_t>(v & 1); }

void Decompressor::RLEDecompress(const std::string& inPath, const std::string& outPath) {
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


/**
 * Re‑create a vanilla little‑endian pcap file from the
 * delta‑encoded stream produced by Compressor::timeDelta().
 *
 *  • inPath  – file written by timeDelta()
 *  • outPath – new .pcap that Wireshark / tcpdump can open
 */
void Decompressor::timeDeltaDecompress(const std::string& inPath,const std::string& outPath) {
    std::ifstream  in(inPath,  std::ios::binary);
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!in || !out) { std::cerr << "I/O error\n"; return; }

    /* ----------  write a minimal global header  ---------- */
    struct PcapGlobalHeader {
        uint32_t magic = 0xa1b2c3d4;      
        uint16_t vMaj  = 2;
        uint16_t vMin  = 4;
        int32_t  thisZone = 0;
        uint32_t sigFigs  = 0;
        uint32_t snapLen  = 65535;
        uint32_t linkType = 1;            // Ethernet
    } gh;
    out.write(reinterpret_cast<char*>(&gh), sizeof(gh));

    /* ----------  read the base timestamp (µs)  ---------- */
    uint64_t baseUs = 0;
    if (!in.read(reinterpret_cast<char*>(&baseUs), sizeof(baseUs))) {
        std::cerr << "Empty delta file\n";  return;
    }
    uint64_t prevUs = baseUs;

    /* helper to pull a VarInt ZigZag from the stream */
    auto readVarInt = [&in](int64_t& val) -> bool {
        uint64_t res = 0;  int shift = 0, byte = 0;
        do {
            byte = in.get(); if (!in) return false;
            res |= uint64_t(byte & 0x7F) << shift;
            shift += 7;
        } while (byte & 0x80);
        val = unzigzag(res);
        return true;
    };

    /* ----------  packet loop  ---------- */
    std::vector<char> buf;
    while (true)
    {
        int64_t delta = 0;
        if (!readVarInt(delta)) break;               // EOF

        int64_t lenSigned = 0;
        if (!readVarInt(lenSigned)) {
            std::cerr << "Truncated length field\n"; break;
        }
        if (lenSigned < 0) {
            std::cerr << "Negative length?!\n"; break;
        }
        size_t capLen = static_cast<size_t>(lenSigned);

        buf.resize(capLen);
        if (!in.read(buf.data(), capLen)) {
            std::cerr << "Truncated packet bytes\n"; break;
        }

        uint64_t absUs = prevUs + delta;
        prevUs = absUs;

        uint32_t ts_sec   =  static_cast<uint32_t>(absUs / 1'000'000ULL);
        uint32_t ts_usec  =  static_cast<uint32_t>(absUs % 1'000'000ULL);
        uint32_t incl_len =  static_cast<uint32_t>(capLen);
        uint32_t orig_len =  incl_len;

        out.write(reinterpret_cast<char*>(&ts_sec),   4);
        out.write(reinterpret_cast<char*>(&ts_usec),  4);
        out.write(reinterpret_cast<char*>(&incl_len), 4);
        out.write(reinterpret_cast<char*>(&orig_len), 4);
        out.write(buf.data(), capLen);
    }
    out.flush();
}

