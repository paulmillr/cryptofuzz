package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func operationJSON(fields map[string]interface{}) []byte {
	encoded, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return encoded
}

func decodeResult[T any]() T {
	var decoded T
	if err := json.Unmarshal(result, &decoded); err != nil {
		panic(fmt.Sprintf("cannot decode result %q: %v", result, err))
	}
	return decoded
}

func hexByte(value string, count int) string {
	return strings.Repeat(value, count)
}

func assertNobleHash(label string, value []byte, expected string) {
	digest := sha256.Sum256(value)
	if hex.EncodeToString(digest[:]) != expected {
		panic(label + " differs from the Noble test vector")
	}
}

func testMLKEMRoundTrip() {
	circl_Cryptofuzz_OpKEM_KeyGen(operationJSON(map[string]interface{}{
		"kemType": idML_KEM_768,
		"seed":    hexByte("00", 64),
	}))
	keys := decodeResult[KEMKeyPairResult]()
	if len(keys.PublicKey) != kemScheme(idML_KEM_768).PublicKeySize() {
		panic("unexpected ML-KEM public key size")
	}
	assertNobleHash("ML-KEM public key", keys.PublicKey, "f95c185fe5b2335d2fc938dd889c6425944acd74376b6952bf1130f720f6ba99")
	assertNobleHash("ML-KEM secret key", keys.SecretKey, "a5e078867af0c0a9702149b3af1adf208dccf878bc9f9e32d4fb028473addd09")

	circl_Cryptofuzz_OpKEM_Encapsulate(operationJSON(map[string]interface{}{
		"kemType":   idML_KEM_768,
		"publicKey": keys.PublicKey,
		"coins":     hexByte("01", 32),
	}))
	encapsulation := decodeResult[KEMEncapsulationResult]()
	assertNobleHash("ML-KEM ciphertext", encapsulation.Ciphertext, "9cfa36b0d7eab6b9e7a524fa813737777bbf33f13a3154efc13149c292659bc5")
	assertNobleHash("ML-KEM shared secret", encapsulation.SharedSecret, "bcf76e0c2b76fd22b8bc3b84f3f97f834849a1b25bd617ccd3e7832fb7e141fd")

	circl_Cryptofuzz_OpKEM_Decapsulate(operationJSON(map[string]interface{}{
		"kemType":    idML_KEM_768,
		"secretKey":  keys.SecretKey,
		"ciphertext": encapsulation.Ciphertext,
	}))
	sharedSecret := decodeResult[ByteSlice]()
	if !bytes.Equal(sharedSecret, encapsulation.SharedSecret) {
		panic("decapsulated ML-KEM shared secret differs")
	}
}

func testXWingRoundTrip() {
	circl_Cryptofuzz_OpKEM_KeyGen(operationJSON(map[string]interface{}{
		"kemType": idX_Wing,
		"seed":    hexByte("04", 32),
	}))
	keys := decodeResult[KEMKeyPairResult]()
	assertNobleHash("X-Wing public key", keys.PublicKey, "bb4ce870113dc866909cc20bb80054c0b811cd3d20ad40ee0e60d9e256188509")
	assertNobleHash("X-Wing secret key", keys.SecretKey, "9f4fb68f3e1dac82202f9aa581ce0bbf1f765df0e9ac3c8c57e20f685abab8ed")

	circl_Cryptofuzz_OpKEM_Encapsulate(operationJSON(map[string]interface{}{
		"kemType":   idX_Wing,
		"publicKey": keys.PublicKey,
		"coins":     hexByte("05", 64),
	}))
	encapsulation := decodeResult[KEMEncapsulationResult]()
	assertNobleHash("X-Wing ciphertext", encapsulation.Ciphertext, "75d9995f8863b561dcdece3378d0e7de653d290ba577619a682cb2ee86042a1a")
	assertNobleHash("X-Wing shared secret", encapsulation.SharedSecret, "e820127a1b29d490b3ee757f2f8d6df0916e980a475461d606b807468308bbcb")

	circl_Cryptofuzz_OpKEM_Decapsulate(operationJSON(map[string]interface{}{
		"kemType":    idX_Wing,
		"secretKey":  keys.SecretKey,
		"ciphertext": encapsulation.Ciphertext,
	}))
	if !bytes.Equal(decodeResult[ByteSlice](), encapsulation.SharedSecret) {
		panic("decapsulated X-Wing shared secret differs")
	}
}

func testMLDSARoundTrip() {
	circl_Cryptofuzz_OpPQSIG_KeyGen(operationJSON(map[string]interface{}{
		"pqSignatureType": idML_DSA_44,
		"seed":            hexByte("02", 32),
	}))
	keys := decodeResult[PQSignatureKeyPairResult]()
	assertNobleHash("ML-DSA public key", keys.PublicKey, "6e66c2c3c57116351798517f8d7c8d86c6ab57e12236799f00b869ae043a2da3")
	assertNobleHash("ML-DSA secret key", keys.SecretKey, "5452c458dde9df6bde92db0152eb688d6a6364896871d5d7857cfe91a0e5e36d")

	circl_Cryptofuzz_OpPQSIG_Sign(operationJSON(map[string]interface{}{
		"pqSignatureType": idML_DSA_44,
		"secretKey":       keys.SecretKey,
		"message":         "616263",
		"context":         "637478",
		"extraEntropy":    "",
	}))
	signature := decodeResult[ByteSlice]()
	assertNobleHash("ML-DSA signature", signature, "30d4da6dea14aa79cde3888d65e82671980ee4dfe7e86332d925c796b07285a3")

	circl_Cryptofuzz_OpPQSIG_Verify(operationJSON(map[string]interface{}{
		"pqSignatureType": idML_DSA_44,
		"publicKey":       keys.PublicKey,
		"message":         "616263",
		"signature":       signature,
		"context":         "637478",
	}))
	if !decodeResult[bool]() {
		panic("generated ML-DSA signature did not verify")
	}
}

func testSLHDSADeterministicRoundTrip() {
	circl_Cryptofuzz_OpPQSIG_KeyGen(operationJSON(map[string]interface{}{
		"pqSignatureType": idSLH_DSA_SHA2_128f,
		"seed":            hexByte("03", 48),
	}))
	keys := decodeResult[PQSignatureKeyPairResult]()
	assertNobleHash("SLH-DSA public key", keys.PublicKey, "931d0ca2c8e4a5d080329837bba0356c9d4a8dcb5bbaaf71388d0acad50d2e4f")
	assertNobleHash("SLH-DSA secret key", keys.SecretKey, "ee23aecd8c021e1964597cf393db33b14abac6e5bbe9e16203b4f104253f84f9")

	signInput := operationJSON(map[string]interface{}{
		"pqSignatureType": idSLH_DSA_SHA2_128f,
		"secretKey":       keys.SecretKey,
		"message":         "616263",
		"context":         "",
		"extraEntropy":    "",
	})
	circl_Cryptofuzz_OpPQSIG_Sign(signInput)
	first := decodeResult[ByteSlice]()
	circl_Cryptofuzz_OpPQSIG_Sign(signInput)
	second := decodeResult[ByteSlice]()
	if !bytes.Equal(first, second) {
		panic("deterministic SLH-DSA signatures differ")
	}
	assertNobleHash("SLH-DSA signature", first, "7b93ce11bbea64b6db2cea794e35f2487fb8382a5f4af52f91d2fe6f185eb5b0")

	circl_Cryptofuzz_OpPQSIG_Verify(operationJSON(map[string]interface{}{
		"pqSignatureType": idSLH_DSA_SHA2_128f,
		"publicKey":       keys.PublicKey,
		"message":         "616263",
		"signature":       first,
		"context":         "",
	}))
	if !decodeResult[bool]() {
		panic("generated SLH-DSA signature did not verify")
	}
}

func init() {
	testMLKEMRoundTrip()
	testXWingRoundTrip()
	testMLDSARoundTrip()
	testSLHDSADeterministicRoundTrip()
	fmt.Println("CIRCL post-quantum adapter tests passed")
}
