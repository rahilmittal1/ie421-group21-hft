#include <iostream>
#include <vector>
#include <cmath>
#include "benchmark.h"

// Naive method: Check if a number is prime
bool isPrimeNaive(int num) {
    if (num < 2) return false;
    for (int i = 2; i <= std::sqrt(num); ++i) {
        if (num % i == 0) return false;
    }
    return true;
}

// Compute sum of primes using naive method (slow)
long long sumPrimesNaive(int N) {
    long long sum = 0;
    for (int i = 2; i <= N; ++i) {
        if (isPrimeNaive(i)) sum += i;
    }
    return sum;
}

// Optimized method: Compute prime sum (fast)
long long sumPrimesSieve(int N) {
    std::vector<bool> isPrime(N + 1, true);
    isPrime[0] = isPrime[1] = false;
    
    for (int i = 2; i * i <= N; ++i) {
        if (isPrime[i]) {
            for (int j = i * i; j <= N; j += i)
                isPrime[j] = false;
        }
    }

    long long sum = 0;
    for (int i = 2; i <= N; ++i) {
        if (isPrime[i]) sum += i;
    }
    return sum;
}

int main() {
    constexpr int N = 1000000; // Large N for meaningful performance difference

    // Benchmark Naive Prime Sum
    std::cout << "Benchmarking Naive Prime Sum...\n";
    double naiveTime = Benchmark::measureFunctionTimeNs([&]() {
        long long sum = sumPrimesNaive(N);
        std::cout << "Naive Prime Sum: " << sum << "\n";
    });
    std::cout << "Naive Prime Sum took " << naiveTime / 1e9 << " seconds\n";

    // Benchmark Optimized Prime Sum (Sieve of Eratosthenes)
    std::cout << "\nBenchmarking Optimized Prime Sum...\n";
    double sieveTime = Benchmark::measureFunctionTimeNs([&]() {
        long long sum = sumPrimesSieve(N);
        std::cout << "Optimized Prime Sum: " << sum << "\n";
    });
    std::cout << "Optimized Prime Sum took " << sieveTime / 1e9 << " seconds\n";

    return 0;
}


/*
RESULTS 

Benchmarking Naive Prime Sum...
Naive Prime Sum: 37550402023
Naive Prime Sum took 0.156156 seconds

Benchmarking Optimized Prime Sum...
Optimized Prime Sum: 37550402023
Optimized Prime Sum took 0.0167633 seconds
*/