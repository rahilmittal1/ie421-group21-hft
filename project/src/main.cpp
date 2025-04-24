#include <iostream>
#include <string>
#include <fstream>
#include "parser/parser.h"

int main() {
    // do_some();
    std::string file_name = "/Users/mahir/Desktop/IE421/project/data/example.pcap";
    // std::string out = "/Users/mahir/Desktop/IE421/project/data/output_example.bin";
    // extractPayload(file_name, out);
    // print_header_sizes(file_name);
    parse_pcap();
}
