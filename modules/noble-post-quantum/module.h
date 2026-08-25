#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class noble_post_quantum : public Module {
    public:
        void* js;
        noble_post_quantum(void);
        ~noble_post_quantum();
        std::optional<component::KEMKeyPair> OpKEM_KeyGen(operation::KEM_KeyGen& op) override;
        std::optional<component::KEMEncapsulation> OpKEM_Encapsulate(operation::KEM_Encapsulate& op) override;
        std::optional<component::SharedSecret> OpKEM_Decapsulate(operation::KEM_Decapsulate& op) override;
        std::optional<component::PQSignatureKeyPair> OpPQSIG_KeyGen(operation::PQSIG_KeyGen& op) override;
        std::optional<component::PQSignature> OpPQSIG_Sign(operation::PQSIG_Sign& op) override;
        std::optional<bool> OpPQSIG_Verify(operation::PQSIG_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
