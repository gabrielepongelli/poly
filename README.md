# Poly

A library to build Polymorphic Viruses.

## Table of Contents
1. [About The Project](#about-the-project)
    - [Built With](#built-with)
2. [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Configurations](#configurations)
    - [Building](#building)
3. [Example](#example)
4. [Documentation](#documentation)
<br>


## About The Project

This project is made for the thesis of my bachelor's degree in Computer Science. It aims at providing an example of polymorphic virus written in a modern language, and is designed to be "easily" customized and extended.

## Built With

This project is built using:
- [LIEF](https://lief-project.github.io): used to parse and modify different binary formats.
- [AsmJit](https://asmjit.com): used to generate assembly code on the fly.
- [Gulrak Filesystem](https://github.com/gulrak/filesystem): used to abstract from the details of different filesystems.
- [Catch2](https://github.com/catchorg/Catch2): used for unit testing.

## Getting Started

### Prerequisites

The code of this project is compatible with Linux, MacOS and Windows (and MinGW), but only on 64 bits systems which run a x86 processor.

> Note: on Linux this project is compatible only with system which use ELF as binary format.

> Note: this project was tested only on the latest MSVC, GCC and Apple Clang.

It is also required:
- C++14
- CMake
- Git

### Configurations

This project uses CMake as build system.
The configuration file makes available this options which are turned off by default:
```cmake
option(POLY_BUILD_TESTING "Build test cases"    OFF)
option(POLY_BUILD_EXAMPLE "Build example"       OFF)
option(POLY_BUILD_DOC     "Build documentation" OFF)
```

### Building

In order to build the project you need to perform the following steps:
1. Clone the repo
   ```sh
   git clone https://github.com/gabrielepongelli/poly.git && cd poly
   ```
2. Configure the project using CMake:
    ```sh
    cmake -S . -B ./build -DCMAKE_BUILD_TYPE=Release
    ```
3. Compile the project:
    ```
    cmake --build ./build --config Release
    ```

> Note: if compiled with the Debug configuration the virus will be much slower that the one compiled with the Release configuration.

## Example

An example of usage of this library can be found [here](https://github.com/gabrielepongelli/poly/tree/main/example).

## Documentation

A detailed documentation of the project' structure can be found [here](https://gabrielepongelli.github.io/poly/).