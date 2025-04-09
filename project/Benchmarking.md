# Benchmarking Guide

## How to Use Benchmarking

### **Include Benchmarking in Your Code**
```cpp
#include "benchmark.h"
```

### **Benchmark Any Function**
Use `Benchmark::measureFunctionTimeNs()` to measure execution time in **nanoseconds**.

#### **Example: Measuring Sorting Speed**
```cpp
std::vector<int> arr = {5, 3, 8, 1, 9};

double timeTaken = Benchmark::measureFunctionTimeNs([&]() {
    std::sort(arr.begin(), arr.end());
});

std::cout << "Sorting took " << timeTaken / 1e9 << " seconds\n";
```

---

## Alternative: Manual Timing  
You can also use `startTimer()` and `stopTimer()`.

#### **Example: Manual Timing**
```cpp
Benchmark::startTimer();
std::sort(arr.begin(), arr.end());
Benchmark::stopTimer("Sorting");
```

---

