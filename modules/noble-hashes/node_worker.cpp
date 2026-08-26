#include "node_worker.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" unsigned char libfuzzer_bytecode_counter[65536];

namespace cryptofuzz {
namespace module {
namespace noble_hashes_detail {
namespace {

[[noreturn]] void ProtocolFailure(void) {
    std::abort();
}

void WriteExact(const int fd, const uint8_t* data, const size_t size) {
    size_t offset = 0;
    while ( offset != size ) {
        const auto count = write(fd, data + offset, size - offset);
        if ( count < 0 && errno == EINTR ) {
            continue;
        }
        if ( count <= 0 ) {
            ProtocolFailure();
        }
        offset += static_cast<size_t>(count);
    }
}

void ReadExact(const int fd, uint8_t* data, const size_t size) {
    size_t offset = 0;
    while ( offset != size ) {
        const auto count = read(fd, data + offset, size - offset);
        if ( count < 0 && errno == EINTR ) {
            continue;
        }
        if ( count <= 0 ) {
            ProtocolFailure();
        }
        offset += static_cast<size_t>(count);
    }
}

void AppendU32(std::vector<uint8_t>& output, const uint32_t value) {
    for (size_t i = 0; i < 4; i++) {
        output.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

void AppendU64(std::vector<uint8_t>& output, const uint64_t value) {
    for (size_t i = 0; i < 8; i++) {
        output.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

uint16_t ReadU16(const std::vector<uint8_t>& input, size_t& offset) {
    if ( offset + 2 > input.size() ) {
        ProtocolFailure();
    }
    const auto value = static_cast<uint16_t>(input[offset]) |
        static_cast<uint16_t>(input[offset + 1]) << 8;
    offset += 2;
    return value;
}

uint32_t ReadU32(const std::vector<uint8_t>& input, size_t& offset) {
    if ( offset + 4 > input.size() ) {
        ProtocolFailure();
    }
    uint32_t value = 0;
    for (size_t i = 0; i < 4; i++) {
        value |= static_cast<uint32_t>(input[offset + i]) << (i * 8);
    }
    offset += 4;
    return value;
}

} /* namespace */

NodeWorker::NodeWorker(
        const std::string& nodeBinary,
        const std::string& workerPath) {
    int requestPipe[2];
    int responsePipe[2];
    if ( pipe(requestPipe) != 0 ) {
        throw std::runtime_error("cannot create Node request pipe");
    }
    if ( pipe(responsePipe) != 0 ) {
        close(requestPipe[0]);
        close(requestPipe[1]);
        throw std::runtime_error("cannot create Node response pipe");
    }

    const auto child = fork();
    if ( child < 0 ) {
        close(requestPipe[0]);
        close(requestPipe[1]);
        close(responsePipe[0]);
        close(responsePipe[1]);
        throw std::runtime_error("cannot fork Node worker");
    }

    if ( child == 0 ) {
        if ( dup2(requestPipe[0], STDIN_FILENO) < 0 ||
                dup2(responsePipe[1], STDOUT_FILENO) < 0 ) {
            _exit(126);
        }
        close(requestPipe[0]);
        close(requestPipe[1]);
        close(responsePipe[0]);
        close(responsePipe[1]);
        execlp(nodeBinary.c_str(), nodeBinary.c_str(), workerPath.c_str(), nullptr);
        _exit(127);
    }

    close(requestPipe[0]);
    close(responsePipe[1]);
    inputFd = requestPipe[1];
    outputFd = responsePipe[0];
    processId = static_cast<int>(child);
}

NodeWorker::~NodeWorker() {
    if ( inputFd >= 0 ) {
        close(inputFd);
    }
    if ( outputFd >= 0 ) {
        close(outputFd);
    }
    if ( processId >= 0 ) {
        int status = 0;
        while ( waitpid(static_cast<pid_t>(processId), &status, 0) < 0 && errno == EINTR ) { }
    }
}

std::optional<std::vector<uint8_t>> NodeWorker::Digest(
        const uint64_t digestType,
        const bool multipart,
        const std::vector<std::pair<const uint8_t*, size_t>>& parts) {
    std::vector<uint8_t> request;
    size_t requestSize = 14;
    for (const auto& part : parts) {
        if ( part.second > std::numeric_limits<uint32_t>::max() ||
                requestSize > std::numeric_limits<uint32_t>::max() - 4 - part.second ) {
            ProtocolFailure();
        }
        requestSize += 4 + part.second;
    }
    if ( parts.size() > std::numeric_limits<uint32_t>::max() ) {
        ProtocolFailure();
    }

    request.reserve(requestSize);
    request.push_back(0);
    AppendU64(request, digestType);
    request.push_back(multipart ? 1 : 0);
    AppendU32(request, static_cast<uint32_t>(parts.size()));
    for (const auto& part : parts) {
        AppendU32(request, static_cast<uint32_t>(part.second));
        if ( part.second != 0 ) {
            request.insert(request.end(), part.first, part.first + part.second);
        }
    }

    return Run(request);
}

std::optional<std::string> NodeWorker::RunJSON(const std::string& input) {
    if ( input.size() >= std::numeric_limits<uint32_t>::max() ) {
        ProtocolFailure();
    }
    std::vector<uint8_t> request;
    request.reserve(input.size() + 1);
    request.push_back(1);
    request.insert(request.end(), input.begin(), input.end());

    const auto result = Run(request);
    if ( result == std::nullopt ) {
        return std::nullopt;
    }
    return std::string(result->begin(), result->end());
}

std::optional<std::vector<uint8_t>> NodeWorker::Run(std::vector<uint8_t>& request) {
    std::vector<uint8_t> header;
    AppendU32(header, static_cast<uint32_t>(request.size()));
    WriteExact(inputFd, header.data(), header.size());
    WriteExact(inputFd, request.data(), request.size());

    uint8_t responseHeader[4];
    ReadExact(outputFd, responseHeader, sizeof(responseHeader));
    const uint32_t responseSize = static_cast<uint32_t>(responseHeader[0]) |
        static_cast<uint32_t>(responseHeader[1]) << 8 |
        static_cast<uint32_t>(responseHeader[2]) << 16 |
        static_cast<uint32_t>(responseHeader[3]) << 24;
    if ( responseSize < 7 || responseSize > 1024 * 1024 ) {
        ProtocolFailure();
    }

    std::vector<uint8_t> response(responseSize);
    ReadExact(outputFd, response.data(), response.size());
    size_t offset = 0;
    const bool haveDigest = response[offset++] != 0;
    const auto digestSize = ReadU32(response, offset);
    if ( digestSize > response.size() - offset ) {
        ProtocolFailure();
    }
    std::vector<uint8_t> digest(
            response.begin() + static_cast<ptrdiff_t>(offset),
            response.begin() + static_cast<ptrdiff_t>(offset + digestSize));
    offset += digestSize;

    const auto coverageCount = ReadU16(response, offset);
    if ( static_cast<size_t>(coverageCount) > (response.size() - offset) / 3 ) {
        ProtocolFailure();
    }
    for (size_t i = 0; i < coverageCount; i++) {
        const auto index = ReadU16(response, offset);
        const auto count = response[offset++];
        libfuzzer_bytecode_counter[index] = static_cast<unsigned char>(
                std::min<unsigned int>(128, libfuzzer_bytecode_counter[index] + count));
    }
    if ( offset != response.size() || (haveDigest == false && digestSize != 0) ) {
        ProtocolFailure();
    }

    if ( haveDigest == false ) {
        return std::nullopt;
    }
    return digest;
}

} /* namespace noble_hashes_detail */
} /* namespace module */
} /* namespace cryptofuzz */
