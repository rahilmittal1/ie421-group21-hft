#include "compressor.h"
#include "decompressor.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <cassert>
#include <filesystem>

/*---------------------------------------------------------*/
/*  Utility: compare original and decompressed byte‑for‑byte */
/*---------------------------------------------------------*/
static void validateFilesEqual(const std::string& original, const std::string& restored, const std::string& label) {
    std::ifstream f1(original, std::ios::binary);
    std::ifstream f2(restored, std::ios::binary);
    std::vector<char> v1{ std::istreambuf_iterator<char>(f1),
                          std::istreambuf_iterator<char>() };
    std::vector<char> v2{ std::istreambuf_iterator<char>(f2),
                          std::istreambuf_iterator<char>() };

    assert(v1 == v2 && (label + " decompression failed!").c_str());
    std::cout << '[' << label << "] Validation passed: output matches input.\n";
}

/*---------------------------------------------------------*/
/*  RLE round‑trip                                         */
/*---------------------------------------------------------*/
static void testRLE(const std::string& input, const std::string& compressed, const std::string& restored) {
    Compressor   c;
    Decompressor d;

    c.RLE(input, compressed);
    d.RLEDecompress(compressed, restored);

    std::cout << "[RLE] Original size:   " << std::filesystem::file_size(input)      << " B\n";
    std::cout << "[RLE] Compressed size: " << std::filesystem::file_size(compressed) << " B\n";

    validateFilesEqual(input, restored, "RLE");
}

/*---------------------------------------------------------*/
/*  Time‑Delta (µs + LEB128) round‑trip                    */
/*---------------------------------------------------------*/
static void testTimeDelta(const std::string& input, const std::string& compressed, const std::string& restored) {
    Compressor   c;
    Decompressor d;

    c.timeDelta(input, compressed);
    d.timeDeltaDecompress(compressed, restored);

    std::cout << "[TimeDelta] Original size:   " << std::filesystem::file_size(input)      << " B\n";
    std::cout << "[TimeDelta] Compressed size: " << std::filesystem::file_size(compressed) << " B\n";

    validateFilesEqual(input, restored, "TimeDelta");
}


/*---------------------------------------------------------*/
/*  Header Deduplication + Restoration round‑trip         */
/*---------------------------------------------------------*/
static void testHeaderRoundTrip(const std::string& input,
    const std::string& compressed,
    const std::string& restored) {
Compressor   c;
Decompressor d;

// Remove duplicate Ethernet/IP/UDP headers
c.removeRepetitiveHeaders(input, compressed);
// Restore full PCAP with headers reinserted
d.RepetitiveHeadersDecompress(compressed, restored);

std::cout << "[HeaderRoundTrip] Original size:   " << std::filesystem::file_size(input)      << " B\n";
std::cout << "[HeaderRoundTrip] Compressed size: " << std::filesystem::file_size(compressed) << " B\n";
std::cout << "[HeaderRoundTrip] Restored size:   " << std::filesystem::file_size(restored)   << " B\n";

// Validate lossless
validateFilesEqual(input, restored, "HeaderRoundTrip");
}

/*---------------------------------------------------------*/
int main()
{
    const std::string inPcap        = "../data/test_small.pcap";
    /* RLE paths */
    const std::string rleOut        = "../data/test_output/test_small.pcap.rle";
    const std::string rleRestored   = "../data/test_output/test_small_decompressed.pcap";
    /* Time‑Delta paths */
    const std::string tdOut         = "../data/test_output/test_small.pcap.tdelta";
    const std::string tdRestored    = "../data/test_output/test_small_tdelta_decompressed.pcap";

    testRLE(inPcap, rleOut, rleRestored);
    testTimeDelta(inPcap, tdOut, tdRestored);
    
    /* Header Removal paths */
    const std::string hdrOut        = "../data/test_output/test_small_headerless.pcap";
    const std::string hdrRestored   = "../data/test_output/test_small_headerless_restored.pcap";
    testHeaderRoundTrip(inPcap, hdrOut, hdrRestored);

    std::cout << "All tests passed.\n";
    return 0;
}
