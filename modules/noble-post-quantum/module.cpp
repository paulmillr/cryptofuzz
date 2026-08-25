#include "module.h"
#include <cryptofuzz/repository.h>
#include "noble-post-quantum.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_post_quantum::noble_post_quantum(void) :
    Module("noble-post-quantum"),
    js(new JS()) {
    const std::vector<uint8_t> bc(
            noble_post_quantum_bytecode,
            noble_post_quantum_bytecode + noble_post_quantum_bytecode_len);
    ((JS*)js)->SetBytecode(bc);
}

noble_post_quantum::~noble_post_quantum(void) {
    delete (JS*)js;
}

template <class Result, class Operation>
static std::optional<Result> Run(JS* js, Operation& op, const uint64_t operationID) {
    auto json = op.ToJSON();
    json["operation"] = std::to_string(operationID);
    const auto res = js->Run(json.dump());
    if ( res == std::nullopt ) {
        return std::nullopt;
    }
    try {
        return Result(nlohmann::json::parse(*res));
    } catch ( const std::exception& ) {
        return std::nullopt;
    }
}

std::optional<component::KEMKeyPair> noble_post_quantum::OpKEM_KeyGen(operation::KEM_KeyGen& op) {
    return Run<component::KEMKeyPair>((JS*)js, op, CF_OPERATION("KEM_KeyGen"));
}

std::optional<component::KEMEncapsulation> noble_post_quantum::OpKEM_Encapsulate(operation::KEM_Encapsulate& op) {
    return Run<component::KEMEncapsulation>((JS*)js, op, CF_OPERATION("KEM_Encapsulate"));
}

std::optional<component::SharedSecret> noble_post_quantum::OpKEM_Decapsulate(operation::KEM_Decapsulate& op) {
    return Run<component::SharedSecret>((JS*)js, op, CF_OPERATION("KEM_Decapsulate"));
}

std::optional<component::PQSignatureKeyPair> noble_post_quantum::OpPQSIG_KeyGen(operation::PQSIG_KeyGen& op) {
    return Run<component::PQSignatureKeyPair>((JS*)js, op, CF_OPERATION("PQSIG_KeyGen"));
}

std::optional<component::PQSignature> noble_post_quantum::OpPQSIG_Sign(operation::PQSIG_Sign& op) {
    return Run<component::PQSignature>((JS*)js, op, CF_OPERATION("PQSIG_Sign"));
}

std::optional<bool> noble_post_quantum::OpPQSIG_Verify(operation::PQSIG_Verify& op) {
    return Run<bool>((JS*)js, op, CF_OPERATION("PQSIG_Verify"));
}

} /* namespace module */
} /* namespace cryptofuzz */
