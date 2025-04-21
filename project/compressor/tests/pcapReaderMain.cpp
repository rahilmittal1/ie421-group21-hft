#include "../src/utils/SimplePcapReader.h"
#include <iostream>

int main(int argc, char* argv[])
{
    if(argc < 2){ std::cerr << "usage: " << argv[0] << " file.pcap\n"; return 1; }
    SimplePcapReader reader(argv[1]);

    PacketView pkt;  uint64_t prev = 0;  size_t i = 0;
    while(reader.readNext(pkt) && i < 20)          // print first 20 records
    {
        uint64_t delta = (i == 0) ? 0 : pkt.absTs - prev;
        prev = pkt.absTs;

        std::cout << i++ << "  ts=" << pkt.absTs
                  << "  Δt=" << delta << " ns"
                  << "  len=" << pkt.len << '\n';
    }
}