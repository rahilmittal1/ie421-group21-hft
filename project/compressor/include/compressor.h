using namespace std;
#include <string>


class Compressor {
    public:
        Compressor();
        ~Compressor();
        void RLE(const std::string& inPath, const std::string& outPath);


    private:
        void compress();
};