#include <algorithm>
#include <cstdio>
#include <string>
#include <cryptofuzz/repository.h>
#include "../../repository_map.h"

namespace {
void PrintID(std::string name, const uint64_t id) {
    std::replace(name.begin(), name.end(), '-', '_');
    std::replace(name.begin(), name.end(), '.', '_');
    std::replace(name.begin(), name.end(), '/', '_');
    std::printf("export const Is%s = function(id) { return id == BigInt(\"%llu\"); }\n",
            name.c_str(), static_cast<unsigned long long>(id));
}
}

int main(void) {
    for (const auto& item : OperationLUTMap) {
        PrintID(item.second.name, item.first);
    }
    for (const auto& item : KEMLUTMap) {
        PrintID(item.second.name, item.first);
    }
    for (const auto& item : PQSIGLUTMap) {
        PrintID(item.second.name, item.first);
    }
    return 0;
}
