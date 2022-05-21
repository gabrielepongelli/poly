#include <fstream>
#include <iostream>

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <return_value> <output_path> [<args..>]\n";
        std::cerr << "Required:\n";
        std::cerr << "\treturn_value: this represents the integer value "
                     "returned by this program if everything is ok.\n";
        std::cerr
            << "\toutput_path: this represents the path of the output file.\n";
        std::cerr << "\nOptional:\n";
        std::cerr << "\targs..: other arguments which will be written inside "
                     "<output_path>\n";

        return 1;
    }

    std::ofstream new_file(argv[2]);

    for (auto i = 3; i < argc; i++) {
        new_file << argv[i] << "\n";
    }

    new_file.close();
    return std::atoi(argv[1]);
}