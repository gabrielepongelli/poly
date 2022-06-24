#if (!defined(_WIN32)) && (!defined(_WIN64))
#include <iostream>

int main(int argc, char **argv) {
    std::cout << "Hello, world!" << std::endl;
    return 0;
}
#else
#include <Windows.h>
#include <iostream>

int main(int argc, char **argv) {
    std::cout << "Hello, world!" << std::endl;
    auto handler = GetCurrentProcess();
    TerminateProcess(handler, 0);
}
#endif