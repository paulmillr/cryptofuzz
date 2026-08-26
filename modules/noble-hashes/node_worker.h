#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace cryptofuzz {
namespace module {
namespace noble_hashes_detail {

class NodeWorker {
    private:
        int inputFd = -1;
        int outputFd = -1;
        int processId = -1;

        std::optional<std::vector<uint8_t>> Run(std::vector<uint8_t>& request);

    public:
        NodeWorker(const std::string& nodeBinary, const std::string& workerPath);
        ~NodeWorker();

        NodeWorker(const NodeWorker&) = delete;
        NodeWorker& operator=(const NodeWorker&) = delete;

        std::optional<std::vector<uint8_t>> Digest(
                uint64_t digestType,
                bool multipart,
                const std::vector<std::pair<const uint8_t*, size_t>>& parts);
        std::optional<std::string> RunJSON(const std::string& input);
};

} /* namespace noble_hashes_detail */
} /* namespace module */
} /* namespace cryptofuzz */
