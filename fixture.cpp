#include <cstdio>
#include <string>
#include <vector>
int main(int argc, char **argv) {
    std::vector<std::string> labels(argv, argv + argc);
    return std::printf("%zu\n", labels.at(0).size()) < 0;
}
