using namespace std;
#include <string>


class Decompressor {
    public:
        Decompressor();
        ~Decompressor();
        void Decompressor::RLEDecompress(const std::string& inputFile, const std::string& outputFile);


    private:
        void deocmpress();
};