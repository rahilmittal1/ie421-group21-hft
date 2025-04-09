#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <chrono>
#include <iostream>
#include <functional>

class Benchmark {
public:
    // Start and Stop Timer
    static void startTimer();
    static void stopTimer(const std::string& label);

    // Template Function to Measure Any Callable
    template <typename Func>
    static double measureFunctionTimeNs(Func func) {
        auto start = std::chrono::high_resolution_clock::now();
        func();  // Execute function/lambda
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    }
};

#endif 
