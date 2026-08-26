#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <utility>

class JS {
    private:
        struct PersistentState;

        std::vector<uint8_t> bytecode;
        size_t memoryLimit;
        std::string entrypoint;
        std::unique_ptr<PersistentState> persistentState;

        void ResetPersistentState(void);
        bool InitializePersistentState(void);
        std::optional<std::string> RunPersistent(const void* data, const size_t size);
        std::optional<std::string> RunFresh(const void* data, const size_t size, const bool asString);
    public:
        JS(void);
        ~JS(void);
        static std::vector<char> LoadFile(const std::string& fn);
        static std::vector<uint8_t> CompileJavascript(const std::string& javascriptFilename);
        void SetBytecode(const std::vector<char>& bytecode);
        void SetBytecode(const std::vector<uint8_t>& bytecode);
        void SetMemoryLimit(const size_t limit);
        void SetEntrypoint(const std::string& name);
        std::optional<std::string> Run(const std::string& data);
        std::optional<std::string> Run(const void* data, const size_t size, const bool asString = false);
        std::optional<std::vector<uint8_t>> RunByteArrays(
                const std::string& functionName,
                const std::vector<std::string>& stringArguments,
                const std::vector<std::pair<const uint8_t*, size_t>>& byteArrays);
};
