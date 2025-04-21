#pragma once
#include <cstdint>
#include <fstream>
#include <vector>
#include <stdexcept>

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic;          // 0xa1b2c3d4 / 0xd4c3b2a1 (µs) or 0xa1b23c4d / 0x4d3cb2a1 (ns)
    uint16_t verMajor;
    uint16_t verMinor;
    int32_t  thisZone;
    uint32_t sigFigs;
    uint32_t snapLen;
    uint32_t linkType;
};

struct PcapRecHeader {
    uint32_t tsSec;
    uint32_t tsSubsec;       // µs or ns depending on magic
    uint32_t inclLen;
    uint32_t origLen;
};
#pragma pack(pop)

/* --------  A very small “view” for one packet  -------- */
struct PacketView {
    uint64_t   absTs;          // nanoseconds since epoch (always NS here)
    const uint8_t* data;       // pointer into internal buffer
    uint32_t  len;             // captured length
};

class SimplePcapReader {
public:
    explicit SimplePcapReader(const std::string& path) { open(path); }
    ~SimplePcapReader() { close(); }

    bool readNext(PacketView& out);    // returns false on EOF
    void reopen(const std::string& path){ close(); open(path); }
    void close() { if (file_.is_open()) file_.close(); }

    /* metadata helpers */
    uint32_t  linkType()  const { return gh_.linkType; }
    uint32_t  snapLen()   const { return gh_.snapLen;  }
    bool      nano()      const { return nano_;        }

private:
    void open(const std::string& path);

    std::ifstream         file_;
    PcapGlobalHeader       gh_{};
    std::vector<uint8_t>   buf_;
    bool                   swap_  = false;
    bool                   nano_  = false;
};

/* ---------------- Implementation ---------------- */
inline uint32_t bswap32(uint32_t x){ return __builtin_bswap32(x); }
inline uint16_t bswap16(uint16_t x){ return __builtin_bswap16(x); }

inline void SimplePcapReader::open(const std::string& path)
{
    file_.open(path, std::ios::binary);
    if(!file_) throw std::runtime_error("Cannot open " + path);

    file_.read(reinterpret_cast<char*>(&gh_), sizeof(gh_));
    if(!file_) throw std::runtime_error("Cannot read global header");

    switch (gh_.magic)
{
    case 0xa1b2c3d4:  // file bytes d4 c3 b2 a1  (µs, little‑endian)
        swap_ = false;  nano_ = false;  break;

    case 0xd4c3b2a1:  // file bytes a1 b2 c3 d4  (µs, big‑endian)
        swap_ = true;   nano_ = false;  break;

    case 0xa1b23c4d:  // file bytes 4d 3c b2 a1  (ns, little‑endian)
        swap_ = false;  nano_ = true;   break;

    case 0x4d3cb2a1:  // file bytes a1 b2 3c 4d  (ns, big‑endian)
        swap_ = true;   nano_ = true;   break;

    default:
        throw std::runtime_error("Unknown pcap magic");
}
    if(swap_){
        gh_.verMajor = bswap16(gh_.verMajor);
        gh_.verMinor = bswap16(gh_.verMinor);
        gh_.snapLen  = bswap32(gh_.snapLen);
        gh_.linkType = bswap32(gh_.linkType);
    }
}

inline bool SimplePcapReader::readNext(PacketView& out)
{
    PcapRecHeader rh;
    if(!file_.read(reinterpret_cast<char*>(&rh), sizeof(rh))) return false;

    if(swap_){
        rh.tsSec   = bswap32(rh.tsSec);
        rh.tsSubsec= bswap32(rh.tsSubsec);
        rh.inclLen = bswap32(rh.inclLen);
        rh.origLen = bswap32(rh.origLen);
    }

    /* read (or grow) buffer */
    if(rh.inclLen > buf_.size()) buf_.resize(rh.inclLen);
    if(!file_.read(reinterpret_cast<char*>(buf_.data()), rh.inclLen))
        throw std::runtime_error("Short read inside packet");

    uint64_t ns = static_cast<uint64_t>(rh.tsSec) * 1'000'000'000ULL +
                  (nano_ ? rh.tsSubsec : rh.tsSubsec * 1'000ULL);

    out.absTs = ns;
    out.data  = buf_.data();
    out.len   = rh.inclLen;
    return true;
}
