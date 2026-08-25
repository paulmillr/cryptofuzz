#pragma once

#include <array>
#include <string>
#include <cstdint>
#include <vector>
#include <optional>

#include <cryptofuzz/config.h>

template <class T, size_t Size>
class MutatorPool {
	private:
		static_assert(Size > 0, "MutatorPool must have at least one slot");
		std::array<T, Size> pool = {};
		std::array<bool, Size> occupied = {};
		size_t occupiedCount = 0;
	public:
		void Set(const T& v);
		bool Have(void) const;
		T Get(void) const;

		template <class Predicate>
		std::optional<T> Find(Predicate predicate) const {
			if ( occupiedCount == 0 ) {
				return std::nullopt;
			}
			for (size_t i = 0; i < Size; i++) {
				if ( occupied[i] && predicate(pool[i]) ) {
					return pool[i];
				}
			}
			return std::nullopt;
		}
};

typedef struct {
    uint64_t curveID;
    std::string priv;
} CurvePrivkey_Pair;
extern MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;

typedef struct {
    uint64_t curveID;
    std::string privkey;
    std::string pub_x;
    std::string pub_y;
} CurveKeypair_Pair;
extern MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;

typedef struct {
    uint64_t curveID;
    std::string cleartext;
    std::string pub_x;
    std::string pub_y;
    std::string sig_r;
    std::string sig_y;
} CurveECDSASignature_Pair;
extern MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;

typedef struct {
    std::string cleartext;
    std::string p;
    std::string q;
    std::string g;
    std::string pub;
    std::string r;
    std::string s;
} DSASignature;
extern MutatorPool<DSASignature, cryptofuzz::config::kMutatorPoolSize> Pool_DSASignature;

typedef struct {
    uint64_t curveID;
    std::string cleartext;
    std::string id;
    std::string pub_x;
    std::string pub_y;
    std::string pvt_x;
    std::string pvt_y;
    std::string sig_r;
    std::string sig_s;
} CurveECCSISignature_Pair;
extern MutatorPool<CurveECCSISignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECCSISignature;

typedef struct {
    uint64_t curveID;
    std::string x;
    std::string y;
} CurveECC_Point_Pair;
extern MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;

extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;
extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum_Primes;

typedef struct {
    uint64_t curveID;
    bool hashOrPoint;
    std::string point_v;
    std::string point_w;
    std::string point_x;
    std::string point_y;
    std::string cleartext;
    std::string dest;
    std::string aug;
    std::string pub_x;
    std::string pub_y;
    std::string sig_v;
    std::string sig_w;
    std::string sig_x;
    std::string sig_y;
} CurveBLSSignature_Pair;
extern MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;

typedef struct {
    uint64_t curveID;
    std::string g1_x;
    std::string g1_y;
} CurveBLSG1_Pair;
extern MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;

typedef struct {
    uint64_t curveID;
    std::string g2_v;
    std::string g2_w;
    std::string g2_x;
    std::string g2_y;
} CurveBLSG2_Pair;
extern MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;

typedef struct {
    std::string bn1;
    std::string bn2;
    std::string bn3;
    std::string bn4;
    std::string bn5;
    std::string bn6;
    std::string bn7;
    std::string bn8;
    std::string bn9;
    std::string bn10;
    std::string bn11;
    std::string bn12;
} Fp12;
extern MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize> Pool_Fp12;

typedef struct BLS_BatchSignature_ {
    struct G1 {
        std::string g1_x;
        std::string g1_y;
    };

    struct G2 {
        std::string g2_v;
        std::string g2_w;
        std::string g2_x;
        std::string g2_y;
    };

    std::vector<
        std::pair<G1, G2>
    > msgpub;
} BLS_BatchSignature_;
extern MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize> Pool_BLS_BatchSignature;

extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
extern MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;

typedef struct {
    std::string p;
    std::string q;
    std::string g;
} DSA_PQG;
extern MutatorPool<DSA_PQG, 8> Pool_DSA_PQG;

typedef struct {
    std::string first;
    std::string second;
} type_DoubleString;

extern MutatorPool<type_DoubleString, 64> Pool_DSA_PubPriv;

typedef struct {
    uint64_t kemID;
    std::string publicKey;
    std::string secretKey;
} KEMKeyPair_PoolEntry;
extern MutatorPool<KEMKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_KEMKeyPair;

typedef struct {
    uint64_t kemID;
    std::string secretKey;
    std::string ciphertext;
    std::string sharedSecret;
} KEMEncapsulation_PoolEntry;
extern MutatorPool<KEMEncapsulation_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_KEMEncapsulation;

typedef struct {
    uint64_t pqSignatureID;
    std::string publicKey;
    std::string secretKey;
} PQSignatureKeyPair_PoolEntry;
extern MutatorPool<PQSignatureKeyPair_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_PQSignatureKeyPair;

typedef struct {
    uint64_t pqSignatureID;
    std::string publicKey;
    std::string message;
    std::string signature;
    std::string context;
} PQSignature_PoolEntry;
extern MutatorPool<PQSignature_PoolEntry, cryptofuzz::config::kMutatorPoolSize> Pool_PQSignature;
