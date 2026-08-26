#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-hashes.bytecode.h"
#include "node_worker.h"
#include "js.h"
#include <cstdlib>
#include <cstring>

namespace cryptofuzz {
namespace module {

noble_hashes::noble_hashes(void) :
    Module("noble-hashes"),
    js(new JS()),
    nodeWorker(nullptr) {

    const std::vector<uint8_t> bc(noble_hashes_bytecode, noble_hashes_bytecode + noble_hashes_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
    ((JS*)js)->SetEntrypoint("CryptofuzzRun");

    const auto useNode = std::getenv("CRYPTOFUZZ_NOBLE_HASHES_NODE");
    if ( useNode != nullptr && std::strcmp(useNode, "1") == 0 ) {
        const auto nodeBinaryEnv = std::getenv("CRYPTOFUZZ_NODE_BINARY");
        const auto workerPathEnv = std::getenv("CRYPTOFUZZ_NOBLE_HASHES_NODE_WORKER");
        const std::string nodeBinary = nodeBinaryEnv == nullptr ? "node" : nodeBinaryEnv;
        const std::string workerPath = workerPathEnv == nullptr ?
            "modules/noble-hashes/node-worker.mjs" : workerPathEnv;
        nodeWorker = new noble_hashes_detail::NodeWorker(nodeBinary, workerPath);
    }
}

noble_hashes::~noble_hashes(void) {
    delete (noble_hashes_detail::NodeWorker*)nodeWorker;
    delete (JS*)js;
}

namespace noble_hashes_detail {
    std::optional<util::Multipart> ToParts(const component::Cleartext& ct, fuzzing::datasource::Datasource& ds) {
        bool toParts  = false;
        try {
            toParts = ds.Get<bool>();
        } catch ( const fuzzing::datasource::Datasource::OutOfData& ) { }

        if ( toParts == false ) {
            return std::nullopt;
        }

        return util::ToParts(ds, ct);
    }

    void AddParts(nlohmann::json& json, const component::Cleartext& ct, fuzzing::datasource::Datasource& ds) {
        const auto parts = noble_hashes_detail::ToParts(ct, ds);

        if ( parts != std::nullopt ) {
            json["haveParts"] = true;
            json["parts"] = nlohmann::json::array();
            for (const auto& part : *parts) {
                const auto part_ = Buffer(part.first, part.second);
                json["parts"].push_back( part_.ToJSON() );
            }
            json.erase("cleartext");
        } else {
            json["haveParts"] = false;
        }
    }
}

std::optional<component::Digest> noble_hashes::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    const auto parts = noble_hashes_detail::ToParts(op.cleartext, ds);
    util::Multipart byteArrays;

    if ( parts == std::nullopt ) {
        byteArrays.emplace_back(op.cleartext.GetPtr(), op.cleartext.GetSize());
    } else {
        byteArrays = *parts;
    }

    std::optional<std::vector<uint8_t>> res;
    if ( nodeWorker != nullptr ) {
        res = ((noble_hashes_detail::NodeWorker*)nodeWorker)->Digest(
                op.digestType.Get(),
                parts != std::nullopt,
                byteArrays);
    } else {
        res = ((JS*)js)->RunByteArrays(
                "CryptofuzzDigest",
                {
                    std::to_string(op.digestType.Get()),
                    parts == std::nullopt ? "0" : "1",
                },
                byteArrays);
    }

    if ( res != std::nullopt ) {
        ret = component::Digest(*res);
    }

    return ret;
}

std::optional<component::MAC> noble_hashes::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    auto json = op.ToJSON();
    json.erase("modifier");
    json["operation"] = std::to_string(CF_OPERATION("HMAC"));

    CF_NORET(noble_hashes_detail::AddParts(json, op.cleartext, ds));

    const auto input = json.dump();
    auto res = nodeWorker == nullptr ?
        ((JS*)js)->Run(input) :
        ((noble_hashes_detail::NodeWorker*)nodeWorker)->RunJSON(input);

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::MAC(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json.erase("modifier");
    json["operation"] = std::to_string(CF_OPERATION("KDF_HKDF"));

    const auto input = json.dump();
    auto res = nodeWorker == nullptr ?
        ((JS*)js)->Run(input) :
        ((noble_hashes_detail::NodeWorker*)nodeWorker)->RunJSON(input);

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json.erase("modifier");
    json["operation"] = std::to_string(CF_OPERATION("KDF_PBKDF2"));

    const auto input = json.dump();
    auto res = nodeWorker == nullptr ?
        ((JS*)js)->Run(input) :
        ((noble_hashes_detail::NodeWorker*)nodeWorker)->RunJSON(input);

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json.erase("modifier");
    json["operation"] = std::to_string(CF_OPERATION("KDF_SCRYPT"));

    const auto input = json.dump();
    auto res = nodeWorker == nullptr ?
        ((JS*)js)->Run(input) :
        ((noble_hashes_detail::NodeWorker*)nodeWorker)->RunJSON(input);

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json.erase("modifier");
    json["operation"] = std::to_string(CF_OPERATION("KDF_ARGON2"));

    const auto input = json.dump();
    auto res = nodeWorker == nullptr ?
        ((JS*)js)->Run(input) :
        ((noble_hashes_detail::NodeWorker*)nodeWorker)->RunJSON(input);

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
