#include "benchmark.h"

// Global start time for manual timing
std::chrono::high_resolution_clock::time_point startTime;

// Start Timer
void Benchmark::startTimer() {
    startTime = std::chrono::high_resolution_clock::now();
}

// Stop Timer and Print Result
void Benchmark::stopTimer(const std::string& label) {
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
    std::cout << label << " execution time: " << duration << " µs" << std::endl;
}
