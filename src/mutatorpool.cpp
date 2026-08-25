#include "mutatorpool.h"

uint32_t PRNG(void);

template <class T, size_t Size>
void MutatorPool<T, Size>::Set(const T& v) {
    const size_t index = PRNG() % Size;
    pool[index] = v;
    if ( !occupied[index] ) {
        occupied[index] = true;
        occupiedCount++;
    }
}

template <class T, size_t Size>
bool MutatorPool<T, Size>::Have(void) const {
	return occupiedCount != 0;
}

template <class T, size_t Size>
T MutatorPool<T, Size>::Get(void) const {
    if ( occupiedCount == 0 ) {
        return T{};
    }

    size_t selected = PRNG() % occupiedCount;
    for (size_t i = 0; i < Size; i++) {
        if ( occupied[i] ) {
            if ( selected == 0 ) {
                return pool[i];
            }
            selected--;
        }
    }

    return T{};
}

MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;
MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;
MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;
MutatorPool<DSASignature, cryptofuzz::config::kMutatorPoolSize> Pool_DSASignature;
MutatorPool<CurveECCSISignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECCSISignature;
MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;
MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;
MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;
MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum_Primes;
MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize> Pool_Fp12;
MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize> Pool_BLS_BatchSignature;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;
MutatorPool<DSA_PQG, 8> Pool_DSA_PQG;
MutatorPool<type_DoubleString, 64> Pool_DSA_PubPriv;
MutatorPool<KEMKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_KEMKeyPair;
MutatorPool<KEMEncapsulation_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_KEMEncapsulation;
MutatorPool<PQSignatureKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_PQSignatureKeyPair;
MutatorPool<PQSignature_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_PQSignature;

template class MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<DSASignature, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECCSISignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<DSA_PQG, 8>;
template class MutatorPool<type_DoubleString, 64>;
template class MutatorPool<KEMKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<KEMEncapsulation_PoolEntry, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<PQSignatureKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<PQSignature_PoolEntry, cryptofuzz::config::kMutatorPoolSize>;
