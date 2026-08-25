#include "module.h"
#include <cryptofuzz/repository.h>
#include "noble-ciphers.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_ciphers::noble_ciphers(void) :
    Module("noble-ciphers"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_ciphers_bytecode, noble_ciphers_bytecode + noble_ciphers_bytecode_len);
    ((JS*)js)->SetBytecode(bc);
}

noble_ciphers::~noble_ciphers(void) {
    delete (JS*)js;
}

namespace noble_ciphers_detail {
    constexpr size_t MaxInputSize = 1024 * 1024;

    std::optional<nlohmann::json> Run(JS* js, nlohmann::json input, const uint64_t operation) {
        input["operation"] = std::to_string(operation);

        const auto result = js->Run(input.dump());
        if ( result == std::nullopt ) {
            return std::nullopt;
        }

        try {
            return nlohmann::json::parse(*result);
        } catch ( const nlohmann::json::exception& ) {
            return std::nullopt;
        }
    }
}

std::optional<component::Ciphertext> noble_ciphers::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    if ( op.cleartext.GetSize() > noble_ciphers_detail::MaxInputSize ||
            op.cipher.key.GetSize() > 64 ||
            op.cipher.iv.GetSize() > noble_ciphers_detail::MaxInputSize ||
            (op.aad != std::nullopt && op.aad->GetSize() > noble_ciphers_detail::MaxInputSize) ) {
        return std::nullopt;
    }

    const auto result = noble_ciphers_detail::Run(
            (JS*)js,
            op.ToJSON(),
            CF_OPERATION("SymmetricEncrypt"));
    if ( result == std::nullopt || !result->is_object() ||
            !result->contains("ciphertext") || !(*result)["ciphertext"].is_string() ) {
        return std::nullopt;
    }

    try {
        std::optional<component::Tag> tag = std::nullopt;
        if ( result->contains("tag") && (*result)["tag"].is_string() ) {
            tag = component::Tag((*result)["tag"]);
        }
        return component::Ciphertext(Buffer((*result)["ciphertext"]), tag);
    } catch ( const nlohmann::json::exception& ) {
        return std::nullopt;
    }
}

std::optional<component::Cleartext> noble_ciphers::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    if ( op.ciphertext.GetSize() > noble_ciphers_detail::MaxInputSize ||
            op.cipher.key.GetSize() > 64 ||
            op.cipher.iv.GetSize() > noble_ciphers_detail::MaxInputSize ||
            (op.aad != std::nullopt && op.aad->GetSize() > noble_ciphers_detail::MaxInputSize) ||
            (op.tag != std::nullopt && op.tag->GetSize() > 16) ) {
        return std::nullopt;
    }

    const auto result = noble_ciphers_detail::Run(
            (JS*)js,
            op.ToJSON(),
            CF_OPERATION("SymmetricDecrypt"));
    if ( result == std::nullopt || !result->is_string() ) {
        return std::nullopt;
    }

    try {
        return component::Cleartext(*result);
    } catch ( const nlohmann::json::exception& ) {
        return std::nullopt;
    }
}

} /* namespace module */
} /* namespace cryptofuzz */
