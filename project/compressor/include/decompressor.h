#ifndef DECOMPRESSOR_H
#define DECOMPRESSOR_H
using namespace std;
#include <string>




class Decompressor {
    public:
        // Decompressor();
        // ~Decompressor();
        void RLEDecompress(const std::string& inputFile, const std::string& outputFile);
        void timeDeltaDecompress(const std::string& inPath,const std::string& outPath);
        void timeDeltaHdrDecompress(const std::string& inPath, const std::string& outPath);


    private:
        
        // void deocmpress();
};



#endif