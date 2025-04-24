#pragma once

class Parser {
    public:

    private:

};

void do_some();

void do_some_2();

void extractPayload(const std::string& pcap_path,
    const std::string& out_bin_path);

void print_header_sizes(const std::string& pcap_path);

void strip_and_parse();

void parse_pcap();