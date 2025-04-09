# Project Guide 

## Structure 

* Benchmarking: Functions to measure performance, latency and speed

* src: Repository for application code (.cpp files)

* include: Folder for include files (.h files)

* build: Build directory for cmake 

## CMakeLists.txt 

Contains all directives and instructions to run the project 

## How to compile 

```bash 

# Clean 
rm -rf build

# Make folder
mkdir build && cd build

# cmake compile
cmake ..

# make 
cmake --build . 
# or 
make 

# run main.cpp
./bin/project
```

Notes:

```bash
build is already made. cd build to enter the folder.
```