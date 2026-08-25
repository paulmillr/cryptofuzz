package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	"math/big"
	"strconv"
	"strings"
)

import "C"

type ByteSlice []byte
type Type uint64

type SliceOpt struct {
	slice ByteSlice
	opt   byte
}

func (t Type) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(t), 10) + `"`), nil
}

func (t *Type) UnmarshalJSON(in []byte) error {
	res, err := strconv.ParseUint(string(in[1:len(in)-1]), 10, 64)
	*t = Type(res)
	return err
}

func (b ByteSlice) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("\"")
	buffer.WriteString(hex.EncodeToString(b))
	buffer.WriteString("\"")
	return buffer.Bytes(), nil
}

func (b *ByteSlice) UnmarshalJSON(in []byte) error {
	res, err := hex.DecodeString(string(in[1 : len(in)-1]))
	*b = res
	return err
}

func decodeBignum(s string) *big.Int {
	if s == "" {
		s = "0"
	}

	bn, ok := new(big.Int).SetString(s, 10)
	if ok == false {
		panic("Cannot decode bignum")
	}
	return bn
}

type OpECC_PrivateToPublic struct {
	Modifier  ByteSlice
	CurveType Type
	Priv      string
}

type OpECC_Point_Add struct {
	Modifier  ByteSlice
	CurveType Type
	A_x       string
	A_y       string
	B_x       string
	B_y       string
}

type OpECC_Point_Mul struct {
	Modifier  ByteSlice
	CurveType Type
	A_x       string
	A_y       string
	B         string
}

type OpECC_Point_Dbl struct {
	Modifier  ByteSlice
	CurveType Type
	A_x       string
	A_y       string
}

type OpBignumCalc struct {
	Modifier ByteSlice
	CalcOp   Type
	BN0      string
	BN1      string
	BN2      string
	BN3      string
}

type OpBLS_PrivateToPublic struct {
	Modifier  ByteSlice
	CurveType uint64
	Priv      string
}

type OpBLS_G1_Add struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	B_x       string
	B_y       string
}

type OpBLS_G1_Mul struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	B         string
}

type OpBLS_G1_Neg struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	B         string
}

type OpBLS_G1_IsEq struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	B_x       string
	B_y       string
}

type OpBLS_IsG1OnCurve struct {
	Modifier  ByteSlice
	CurveType uint64
	G1_x      string
	G1_y      string
}

type OpBLS_HashToG1 struct {
	Modifier  ByteSlice
	CurveType uint64
	Cleartext ByteSlice
	Dest      ByteSlice
	Aug       ByteSlice
}

type OpBLS_PrivateToPublic_G2 struct {
	Modifier  ByteSlice
	CurveType uint64
	Priv      string
}

type OpBLS_G2_Add struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	A_v       string
	A_w       string
	B_x       string
	B_y       string
	B_v       string
	B_w       string
}

type OpBLS_G2_Mul struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	A_v       string
	A_w       string
	B         string
}

type OpBLS_G2_Neg struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	A_v       string
	A_w       string
}

type OpBLS_IsG2OnCurve struct {
	Modifier  ByteSlice
	CurveType uint64
	G2_x      string
	G2_y      string
	G2_v      string
	G2_w      string
}

type OpBLS_G2_IsEq struct {
	Modifier  ByteSlice
	CurveType uint64
	A_x       string
	A_y       string
	A_v       string
	A_w       string
	B_x       string
	B_y       string
	B_v       string
	B_w       string
}

type OpBLS_HashToG2 struct {
	Modifier  ByteSlice
	CurveType uint64
	Cleartext ByteSlice
	Dest      ByteSlice
	Aug       ByteSlice
}

type OpBLS_Decompress_G1 struct {
	Modifier   ByteSlice
	CurveType  uint64
	Compressed string
}

type OpBLS_Compress_G1 struct {
	Modifier  ByteSlice
	CurveType uint64
	G1_x      string
	G1_y      string
}

type OpBLS_Pairing struct {
	Modifier  ByteSlice
	CurveType uint64
	G1_x      string
	G1_y      string

	G2_v string
	G2_w string
	G2_x string
	G2_y string
}

type OpKEM_KeyGen struct {
	Modifier ByteSlice
	KemType  Type
	Seed     ByteSlice
}

type OpKEM_Encapsulate struct {
	Modifier  ByteSlice
	KemType   Type
	PublicKey ByteSlice
	Coins     ByteSlice
}

type OpKEM_Decapsulate struct {
	Modifier   ByteSlice
	KemType    Type
	SecretKey  ByteSlice
	Ciphertext ByteSlice
}

type OpPQSIG_KeyGen struct {
	Modifier        ByteSlice
	PqSignatureType Type
	Seed            ByteSlice
}

type OpPQSIG_Sign struct {
	Modifier        ByteSlice
	PqSignatureType Type
	SecretKey       ByteSlice
	Message         ByteSlice
	Context         ByteSlice
	ExtraEntropy    ByteSlice
}

type OpPQSIG_Verify struct {
	Modifier        ByteSlice
	PqSignatureType Type
	PublicKey       ByteSlice
	Message         ByteSlice
	Signature       ByteSlice
	Context         ByteSlice
}

type KEMKeyPairResult struct {
	PublicKey ByteSlice `json:"publicKey"`
	SecretKey ByteSlice `json:"secretKey"`
}

type KEMEncapsulationResult struct {
	Ciphertext   ByteSlice `json:"ciphertext"`
	SharedSecret ByteSlice `json:"sharedSecret"`
}

type PQSignatureKeyPairResult struct {
	PublicKey ByteSlice `json:"publicKey"`
	SecretKey ByteSlice `json:"secretKey"`
}

var result []byte

func resetResult() {
	result = []byte{}
}

func setResult(r ByteSlice) {
	r2, err := json.Marshal(&r)
	if err != nil {
		panic("Cannot marshal to JSON")
	}
	result = r2
}

func setJSON(value interface{}) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("Cannot marshal result to JSON")
	}
	result = encoded
}

func kemScheme(t Type) kem.Scheme {
	if isML_KEM_512(t) {
		return mlkem512.Scheme()
	}
	if isML_KEM_768(t) {
		return mlkem768.Scheme()
	}
	if isML_KEM_1024(t) {
		return mlkem1024.Scheme()
	}
	if isX_Wing(t) {
		return xwing.Scheme()
	}
	return nil
}

func pqSignatureScheme(t Type) sign.Scheme {
	if isML_DSA_44(t) {
		return mldsa44.Scheme()
	}
	if isML_DSA_65(t) {
		return mldsa65.Scheme()
	}
	if isML_DSA_87(t) {
		return mldsa87.Scheme()
	}
	if isSLH_DSA_SHA2_128f(t) {
		return slhdsa.SHA2_128f.Scheme()
	}
	if isSLH_DSA_SHA2_128s(t) {
		return slhdsa.SHA2_128s.Scheme()
	}
	if isSLH_DSA_SHA2_192f(t) {
		return slhdsa.SHA2_192f.Scheme()
	}
	if isSLH_DSA_SHA2_192s(t) {
		return slhdsa.SHA2_192s.Scheme()
	}
	if isSLH_DSA_SHA2_256f(t) {
		return slhdsa.SHA2_256f.Scheme()
	}
	if isSLH_DSA_SHA2_256s(t) {
		return slhdsa.SHA2_256s.Scheme()
	}
	if isSLH_DSA_SHAKE_128f(t) {
		return slhdsa.SHAKE_128f.Scheme()
	}
	if isSLH_DSA_SHAKE_128s(t) {
		return slhdsa.SHAKE_128s.Scheme()
	}
	if isSLH_DSA_SHAKE_192f(t) {
		return slhdsa.SHAKE_192f.Scheme()
	}
	if isSLH_DSA_SHAKE_192s(t) {
		return slhdsa.SHAKE_192s.Scheme()
	}
	if isSLH_DSA_SHAKE_256f(t) {
		return slhdsa.SHAKE_256f.Scheme()
	}
	if isSLH_DSA_SHAKE_256s(t) {
		return slhdsa.SHAKE_256s.Scheme()
	}
	return nil
}

func slhSignatureID(t Type) (slhdsa.ID, bool) {
	if isSLH_DSA_SHA2_128f(t) {
		return slhdsa.SHA2_128f, true
	}
	if isSLH_DSA_SHA2_128s(t) {
		return slhdsa.SHA2_128s, true
	}
	if isSLH_DSA_SHA2_192f(t) {
		return slhdsa.SHA2_192f, true
	}
	if isSLH_DSA_SHA2_192s(t) {
		return slhdsa.SHA2_192s, true
	}
	if isSLH_DSA_SHA2_256f(t) {
		return slhdsa.SHA2_256f, true
	}
	if isSLH_DSA_SHA2_256s(t) {
		return slhdsa.SHA2_256s, true
	}
	if isSLH_DSA_SHAKE_128f(t) {
		return slhdsa.SHAKE_128f, true
	}
	if isSLH_DSA_SHAKE_128s(t) {
		return slhdsa.SHAKE_128s, true
	}
	if isSLH_DSA_SHAKE_192f(t) {
		return slhdsa.SHAKE_192f, true
	}
	if isSLH_DSA_SHAKE_192s(t) {
		return slhdsa.SHAKE_192s, true
	}
	if isSLH_DSA_SHAKE_256f(t) {
		return slhdsa.SHAKE_256f, true
	}
	if isSLH_DSA_SHAKE_256s(t) {
		return slhdsa.SHAKE_256s, true
	}
	return 0, false
}

func unmarshal(in []byte, op interface{}) {
	err := json.Unmarshal(in, &op)
	if err != nil {
		panic("Cannot unmarshal JSON, which is expected to be well-formed")
	}
}

//export circl_Cryptofuzz_GetResult
func circl_Cryptofuzz_GetResult() *C.char {
	return C.CString(string(result))
}

//export circl_Cryptofuzz_OpECC_PrivateToPublic
func circl_Cryptofuzz_OpECC_PrivateToPublic(in []byte) {
	resetResult()

	var op OpECC_PrivateToPublic
	unmarshal(in, &op)

	if !issecp384r1(op.CurveType) {
		return
	}

	curve := p384.P384()

	b := decodeBignum(op.Priv)

	res_x, res_y := curve.ScalarBaseMult(b.Bytes())

	res := make([]string, 2)
	res[0], res[1] = res_x.String(), res_y.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_Cryptofuzz_OpECC_Point_Add
func circl_Cryptofuzz_OpECC_Point_Add(in []byte) {
	resetResult()

	var op OpECC_Point_Add
	unmarshal(in, &op)

	if !issecp384r1(op.CurveType) {
		return
	}

	curve := p384.P384()

	a_x := decodeBignum(op.A_x)
	a_y := decodeBignum(op.A_y)

	b_x := decodeBignum(op.B_x)
	b_y := decodeBignum(op.B_y)

	res_x, res_y := curve.Add(a_x, a_y, b_x, b_y)

	if curve.IsOnCurve(a_x, a_y) == false {
		return
	}

	if curve.IsOnCurve(b_x, b_y) == false {
		return
	}

	res := make([]string, 2)
	res[0], res[1] = res_x.String(), res_y.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_Cryptofuzz_OpECC_Point_Mul
func circl_Cryptofuzz_OpECC_Point_Mul(in []byte) {
	resetResult()

	var op OpECC_Point_Mul
	unmarshal(in, &op)

	if !issecp384r1(op.CurveType) {
		return
	}

	curve := p384.P384()

	a_x := decodeBignum(op.A_x)
	a_y := decodeBignum(op.A_y)

	b := decodeBignum(op.B)

	res_x, res_y := curve.ScalarMult(a_x, a_y, b.Bytes())

	if curve.IsOnCurve(a_x, a_y) == false {
		return
	}

	res := make([]string, 2)
	res[0], res[1] = res_x.String(), res_y.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_Cryptofuzz_OpECC_Point_Dbl
func circl_Cryptofuzz_OpECC_Point_Dbl(in []byte) {
	resetResult()

	var op OpECC_Point_Dbl
	unmarshal(in, &op)

	if !issecp384r1(op.CurveType) {
		return
	}

	curve := p384.P384()

	a_x := decodeBignum(op.A_x)
	a_y := decodeBignum(op.A_y)

	res_x, res_y := curve.Double(a_x, a_y)

	if curve.IsOnCurve(a_x, a_y) == false {
		return
	}

	res := make([]string, 2)
	res[0], res[1] = res_x.String(), res_y.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_bn254_BignumCalc_Fp
func circl_bn254_BignumCalc_Fp(in []byte) {
	resetResult()

	var op OpBignumCalc
	unmarshal(in, &op)

	var bn0 ff.Fp
	var bn1 ff.Fp
	var r ff.Fp

	err := bn0.SetString(strings.TrimLeft(op.BN0, "0"))
	if err != nil {
		return
	}

	err = bn1.SetString(strings.TrimLeft(op.BN1, "0"))
	if err != nil {
		return
	}

	success := false

	if false {
	} else if isAdd(op.CalcOp) {
		r.Add(&bn0, &bn1)
		success = true
	} else if isSub(op.CalcOp) {
		r.Sub(&bn0, &bn1)
		success = true
	} else if isMul(op.CalcOp) {
		r.Mul(&bn0, &bn1)
		success = true
	} else if isSqr(op.CalcOp) {
		r.Sqr(&bn0)
		success = true
	} else if isInvMod(op.CalcOp) {
		r.Inv(&bn0)
		success = true
	} else if isSqrt(op.CalcOp) {
		if r.Sqrt(&bn0) == 1 {
			r.Sqr(&r)
		}
		success = true
	}

	if success == false {
		return
	}

	b, ok := new(big.Int).SetString(r.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}
	res := b.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_bn254_BignumCalc_Fr
func circl_bn254_BignumCalc_Fr(in []byte) {
	resetResult()

	var op OpBignumCalc
	unmarshal(in, &op)

	var bn0 ff.Scalar
	var bn1 ff.Scalar
	var r ff.Scalar

	err := bn0.SetString(strings.TrimLeft(op.BN0, "0"))
	if err != nil {
		return
	}

	err = bn1.SetString(strings.TrimLeft(op.BN1, "0"))
	if err != nil {
		return
	}

	success := false

	if false {
	} else if isAdd(op.CalcOp) {
		r.Add(&bn0, &bn1)
		success = true
	} else if isSub(op.CalcOp) {
		r.Sub(&bn0, &bn1)
		success = true
	} else if isMul(op.CalcOp) {
		r.Mul(&bn0, &bn1)
		success = true
	} else if isSqr(op.CalcOp) {
		r.Sqr(&bn0)
		success = true
	} else if isInvMod(op.CalcOp) {
		r.Inv(&bn0)
		success = true
	}

	if success == false {
		return
	}

	b, ok := new(big.Int).SetString(r.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}
	res := b.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

func encode_G1(x, y string) (*bls12381.G1, error) {
	a := new(bls12381.G1)
	var a_x ff.Fp
	var a_y ff.Fp

	err := a_x.SetString(strings.TrimLeft(x, "0"))
	if err != nil {
		return nil, err
	}

	err = a_y.SetString(strings.TrimLeft(y, "0"))
	if err != nil {
		return nil, err
	}

	a_bytes, _ := a_x.MarshalBinary()
	a_y_bytes, _ := a_y.MarshalBinary()
	a_bytes = append(a_bytes, a_y_bytes...)
	a_bytes[0] = a_bytes[0] & 0x1F

	err = a.SetBytes(a_bytes)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func encode_G2(v, w, x, y string) (*bls12381.G2, error) {
	a := new(bls12381.G2)
	var a_v ff.Fp
	var a_w ff.Fp
	var a_x ff.Fp
	var a_y ff.Fp

	err := a_v.SetString(strings.TrimLeft(v, "0"))
	if err != nil {
		return nil, err
	}

	err = a_w.SetString(strings.TrimLeft(w, "0"))
	if err != nil {
		return nil, err
	}

	err = a_x.SetString(strings.TrimLeft(x, "0"))
	if err != nil {
		return nil, err
	}

	err = a_y.SetString(strings.TrimLeft(y, "0"))
	if err != nil {
		return nil, err
	}

	a_bytes, _ := a_v.MarshalBinary()
	a_w_bytes, _ := a_w.MarshalBinary()
	a_x_bytes, _ := a_x.MarshalBinary()
	a_y_bytes, _ := a_y.MarshalBinary()
	a_bytes = append(a_bytes, a_w_bytes...)
	a_bytes = append(a_bytes, a_x_bytes...)
	a_bytes = append(a_bytes, a_y_bytes...)
	a_bytes[0] = a_bytes[0] & 0x1F

	err = a.SetBytes(a_bytes)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func save_G1(r *bls12381.G1) {
	var r_x ff.Fp
	var r_y ff.Fp

	r_bytes := r.Bytes()

	x := (&[ff.FpSize]byte{})[:]
	copy(x, r_bytes)
	x[0] &= 0x1F
	if err := r_x.UnmarshalBinary(x); err != nil {
		panic("Cannot decode result")
	}
	if err := r_y.UnmarshalBinary(r_bytes[ff.FpSize:(2 * ff.FpSize)]); err != nil {
		panic("Cannot decode result")
	}

	x_b, ok := new(big.Int).SetString(r_x.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	y_b, ok := new(big.Int).SetString(r_y.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	res := make([]string, 2)

	res[0], res[1] = x_b.String(), y_b.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

func save_G2(r *bls12381.G2) {
	var r_v ff.Fp
	var r_w ff.Fp
	var r_x ff.Fp
	var r_y ff.Fp

	r_bytes := r.Bytes()

	x := (&[ff.FpSize]byte{})[:]
	copy(x, r_bytes)
	x[0] &= 0x1F
	if err := r_x.UnmarshalBinary(x); err != nil {
		panic("Cannot decode result")
	}
	if err := r_y.UnmarshalBinary(r_bytes[ff.FpSize:(2 * ff.FpSize)]); err != nil {
		panic("Cannot decode result")
	}
	if err := r_v.UnmarshalBinary(r_bytes[ff.FpSize*2 : (3 * ff.FpSize)]); err != nil {
		panic("Cannot decode result")
	}
	if err := r_w.UnmarshalBinary(r_bytes[ff.FpSize*3 : (4 * ff.FpSize)]); err != nil {
		panic("Cannot decode result")
	}

	x_b, ok := new(big.Int).SetString(r_x.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	y_b, ok := new(big.Int).SetString(r_y.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	v_b, ok := new(big.Int).SetString(r_v.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	w_b, ok := new(big.Int).SetString(r_w.String()[2:], 16)
	if ok == false {
		panic("Cannot parse circl output")
	}

	res := make([][]string, 2)
	res[0] = make([]string, 2)
	res[1] = make([]string, 2)

	res[0][0] = y_b.String()
	res[0][1] = w_b.String()
	res[1][0] = x_b.String()
	res[1][1] = v_b.String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

func save_Gt(v *bls12381.Gt) {
	res := make([]string, 12)

	bin, err := v.MarshalBinary()
	if err != nil {
		panic("Gt.MarshalBinary failed")
	}
	res[11] = new(big.Int).SetBytes(bin[(48 * 0):(48 * 1)]).String()
	res[10] = new(big.Int).SetBytes(bin[(48 * 1):(48 * 2)]).String()
	res[9] = new(big.Int).SetBytes(bin[(48 * 2):(48 * 3)]).String()
	res[8] = new(big.Int).SetBytes(bin[(48 * 3):(48 * 4)]).String()
	res[7] = new(big.Int).SetBytes(bin[(48 * 4):(48 * 5)]).String()
	res[6] = new(big.Int).SetBytes(bin[(48 * 5):(48 * 6)]).String()
	res[5] = new(big.Int).SetBytes(bin[(48 * 6):(48 * 7)]).String()
	res[4] = new(big.Int).SetBytes(bin[(48 * 7):(48 * 8)]).String()
	res[3] = new(big.Int).SetBytes(bin[(48 * 8):(48 * 9)]).String()
	res[2] = new(big.Int).SetBytes(bin[(48 * 9):(48 * 10)]).String()
	res[1] = new(big.Int).SetBytes(bin[(48 * 10):(48 * 11)]).String()
	res[0] = new(big.Int).SetBytes(bin[(48 * 11):(48 * 12)]).String()

	r2, err := json.Marshal(&res)

	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_PrivateToPublic
func circl_BLS_PrivateToPublic(in []byte) {
	resetResult()

	var op OpBLS_PrivateToPublic
	unmarshal(in, &op)

	a := bls12381.G1Generator()

	var b ff.Scalar

	err := b.SetString(strings.TrimLeft(op.Priv, "0"))
	if err != nil {
		return
	}

	r := new(bls12381.G1)
	r.ScalarMult(&b, a)

	if a.IsOnG1() == false {
		return
	}

	save_G1(r)
}

//export circl_BLS_G1_Add
func circl_BLS_G1_Add(in []byte) {
	resetResult()

	var op OpBLS_G1_Add
	unmarshal(in, &op)

	a, err := encode_G1(op.A_x, op.A_y)
	if err != nil {
		return
	}

	b, err := encode_G1(op.B_x, op.B_y)
	if err != nil {
		return
	}

	r := new(bls12381.G1)

	dbl := false

	if len(op.Modifier) > 0 && op.Modifier[0]&1 == 1 {
		if a.IsEqual(b) {
			dbl = true
		}
	}

	if dbl == true {
		a.Double()
		r = a
	} else {
		r.Add(a, b)
	}

	if a.IsOnG1() == false {
		return
	}
	if b.IsOnG1() == false {
		return
	}

	save_G1(r)
}

//export circl_BLS_G1_Mul
func circl_BLS_G1_Mul(in []byte) {
	resetResult()

	var op OpBLS_G1_Mul
	unmarshal(in, &op)

	a, err := encode_G1(op.A_x, op.A_y)
	if err != nil {
		return
	}

	var b ff.Scalar

	err = b.SetString(strings.TrimLeft(op.B, "0"))
	if err != nil {
		return
	}

	r := new(bls12381.G1)
	r.ScalarMult(&b, a)

	if a.IsOnG1() == false {
		return
	}

	save_G1(r)
}

//export circl_BLS_G1_Neg
func circl_BLS_G1_Neg(in []byte) {
	resetResult()

	var op OpBLS_G1_Neg
	unmarshal(in, &op)

	a, err := encode_G1(op.A_x, op.A_y)
	if err != nil {
		return
	}

	a.Neg()

	save_G1(a)

}

//export circl_BLS_IsG1OnCurve
func circl_BLS_IsG1OnCurve(in []byte) {
	resetResult()

	var op OpBLS_IsG1OnCurve
	unmarshal(in, &op)

	a, err := encode_G1(op.G1_x, op.G1_y)
	if err != nil {
		return
	}

	res := a.IsOnG1()

	r2, err := json.Marshal(&res)

	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_G1_IsEq
func circl_BLS_G1_IsEq(in []byte) {
	resetResult()

	var op OpBLS_G1_IsEq
	unmarshal(in, &op)

	a, err := encode_G1(op.A_x, op.A_y)
	if err != nil {
		return
	}

	b, err := encode_G1(op.B_x, op.B_y)
	if err != nil {
		return
	}

	res := a.IsEqual(b)

	if a.IsOnG1() == false {
		return
	}
	if b.IsOnG1() == false {
		return
	}

	r2, err := json.Marshal(&res)

	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_HashToG1
func circl_BLS_HashToG1(in []byte) {
	resetResult()

	var op OpBLS_HashToG1
	unmarshal(in, &op)

	op.Cleartext = append(op.Aug, op.Cleartext...)

	a := new(bls12381.G1)
	a.Hash(op.Cleartext, op.Dest)

	save_G1(a)
}

//export circl_BLS_G2_Add
func circl_BLS_G2_Add(in []byte) {
	resetResult()

	var op OpBLS_G2_Add
	unmarshal(in, &op)

	a, err := encode_G2(op.A_x, op.A_v, op.A_y, op.A_w)
	if err != nil {
		return
	}

	b, err := encode_G2(op.B_x, op.B_v, op.B_y, op.B_w)
	if err != nil {
		return
	}

	r := new(bls12381.G2)
	dbl := false

	if len(op.Modifier) > 0 && op.Modifier[0]&1 == 1 {
		if a.IsEqual(b) {
			dbl = true
		}
	}

	if dbl == true {
		a.Double()
		r = a
	} else {
		r.Add(a, b)
	}

	if a.IsOnG2() == false {
		return
	}
	if b.IsOnG2() == false {
		return
	}

	save_G2(r)
}

//export circl_BLS_G2_Mul
func circl_BLS_G2_Mul(in []byte) {
	resetResult()

	var op OpBLS_G2_Mul
	unmarshal(in, &op)

	a, err := encode_G2(op.A_x, op.A_v, op.A_y, op.A_w)
	if err != nil {
		return
	}

	var b ff.Scalar

	err = b.SetString(strings.TrimLeft(op.B, "0"))
	if err != nil {
		return
	}

	r := new(bls12381.G2)
	r.ScalarMult(&b, a)

	if a.IsOnG2() == false {
		return
	}

	save_G2(r)
}

//export circl_BLS_PrivateToPublic_G2
func circl_BLS_PrivateToPublic_G2(in []byte) {
	resetResult()

	var op OpBLS_PrivateToPublic_G2
	unmarshal(in, &op)

	a := bls12381.G2Generator()

	var b ff.Scalar

	err := b.SetString(strings.TrimLeft(op.Priv, "0"))
	if err != nil {
		return
	}

	r := new(bls12381.G2)
	r.ScalarMult(&b, a)

	if a.IsOnG2() == false {
		return
	}

	save_G2(r)
}

//export circl_BLS_G2_Neg
func circl_BLS_G2_Neg(in []byte) {
	resetResult()

	var op OpBLS_G2_Neg
	unmarshal(in, &op)

	a, err := encode_G2(op.A_x, op.A_v, op.A_y, op.A_w)
	if err != nil {
		return
	}

	a.Neg()

	save_G2(a)
}

//export circl_BLS_IsG2OnCurve
func circl_BLS_IsG2OnCurve(in []byte) {
	resetResult()

	var op OpBLS_IsG2OnCurve
	unmarshal(in, &op)

	a, err := encode_G2(op.G2_x, op.G2_v, op.G2_y, op.G2_w)
	if err != nil {
		return
	}

	res := a.IsOnG2()

	r2, err := json.Marshal(&res)

	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_G2_IsEq
func circl_BLS_G2_IsEq(in []byte) {
	resetResult()

	var op OpBLS_G2_IsEq
	unmarshal(in, &op)

	a, err := encode_G2(op.A_x, op.A_v, op.A_y, op.A_w)
	if err != nil {
		return
	}

	b, err := encode_G2(op.B_x, op.B_v, op.B_y, op.B_w)
	if err != nil {
		return
	}

	res := a.IsEqual(b)

	if a.IsOnG2() == false {
		return
	}
	if b.IsOnG2() == false {
		return
	}

	r2, err := json.Marshal(&res)

	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_HashToG2
func circl_BLS_HashToG2(in []byte) {
	resetResult()

	var op OpBLS_HashToG2
	unmarshal(in, &op)

	op.Cleartext = append(op.Aug, op.Cleartext...)

	a := new(bls12381.G2)
	a.Hash(op.Cleartext, op.Dest)

	save_G2(a)
}

//export circl_BLS_Decompress_G1
func circl_BLS_Decompress_G1(in []byte) {
	resetResult()

	var op OpBLS_Decompress_G1
	unmarshal(in, &op)

	compressed := decodeBignum(op.Compressed)
	bytes := compressed.Bytes()

	/* circl will panic on certain inputs not compliant with zcash format */
	/* This is expected, see OSS-Fuzz #69580 */
	if len(bytes) > 0 && len(bytes) < 96 {
		/* Infinity */
		if int((bytes[0]>>6)&0x1) == 1 {
			/* Uncompressed */
			if int((bytes[0]>>7)&0x1) == 0 {
				return
			}
		}
	}

	a := new(bls12381.G1)

	err := a.SetBytes(bytes)
	if err != nil {
		return
	}

	save_G1(a)
}

//export circl_BLS_Compress_G1
func circl_BLS_Compress_G1(in []byte) {
	resetResult()

	var op OpBLS_Compress_G1
	unmarshal(in, &op)

	a, err := encode_G1(op.G1_x, op.G1_y)
	if err != nil {
		return
	}

	res := new(big.Int).SetBytes(a.BytesCompressed()).String()

	r2, err := json.Marshal(&res)
	if err != nil {
		panic("Cannot marshal to JSON")
	}

	result = r2
}

//export circl_BLS_Pairing
func circl_BLS_Pairing(in []byte) {
	resetResult()

	var op OpBLS_Pairing
	unmarshal(in, &op)

	g1, err := encode_G1(op.G1_x, op.G1_y)
	if err != nil {
		return
	}

	g2, err := encode_G2(op.G2_x, op.G2_v, op.G2_y, op.G2_w)
	if err != nil {
		return
	}

	paired := bls12381.Pair(g1, g2)
	save_Gt(paired)
}

//export circl_Cryptofuzz_OpKEM_KeyGen
func circl_Cryptofuzz_OpKEM_KeyGen(in []byte) {
	resetResult()

	var op OpKEM_KeyGen
	unmarshal(in, &op)
	scheme := kemScheme(op.KemType)
	if scheme == nil || len(op.Seed) != scheme.SeedSize() {
		return
	}

	publicKey, secretKey := scheme.DeriveKeyPair(op.Seed)
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return
	}
	secretBytes, err := secretKey.MarshalBinary()
	if err != nil {
		return
	}
	setJSON(KEMKeyPairResult{PublicKey: publicBytes, SecretKey: secretBytes})
}

//export circl_Cryptofuzz_OpKEM_Encapsulate
func circl_Cryptofuzz_OpKEM_Encapsulate(in []byte) {
	resetResult()

	var op OpKEM_Encapsulate
	unmarshal(in, &op)
	scheme := kemScheme(op.KemType)
	if scheme == nil || len(op.Coins) != scheme.EncapsulationSeedSize() {
		return
	}
	publicKey, err := scheme.UnmarshalBinaryPublicKey(op.PublicKey)
	if err != nil {
		return
	}
	ciphertext, sharedSecret, err := scheme.EncapsulateDeterministically(publicKey, op.Coins)
	if err != nil {
		return
	}
	setJSON(KEMEncapsulationResult{Ciphertext: ciphertext, SharedSecret: sharedSecret})
}

//export circl_Cryptofuzz_OpKEM_Decapsulate
func circl_Cryptofuzz_OpKEM_Decapsulate(in []byte) {
	resetResult()

	var op OpKEM_Decapsulate
	unmarshal(in, &op)
	scheme := kemScheme(op.KemType)
	if scheme == nil || len(op.Ciphertext) != scheme.CiphertextSize() {
		return
	}
	secretKey, err := scheme.UnmarshalBinaryPrivateKey(op.SecretKey)
	if err != nil {
		return
	}
	sharedSecret, err := scheme.Decapsulate(secretKey, op.Ciphertext)
	if err != nil {
		return
	}
	setResult(sharedSecret)
}

//export circl_Cryptofuzz_OpPQSIG_KeyGen
func circl_Cryptofuzz_OpPQSIG_KeyGen(in []byte) {
	resetResult()

	var op OpPQSIG_KeyGen
	unmarshal(in, &op)
	scheme := pqSignatureScheme(op.PqSignatureType)
	if scheme == nil {
		return
	}
	if id, ok := slhSignatureID(op.PqSignatureType); ok {
		seedSize := 3 * scheme.PublicKeySize() / 2
		if len(op.Seed) != seedSize {
			return
		}
		publicKey, secretKey, err := slhdsa.GenerateKey(bytes.NewReader(op.Seed), id)
		if err != nil {
			return
		}
		publicBytes, err := publicKey.MarshalBinary()
		if err != nil {
			return
		}
		secretBytes, err := secretKey.MarshalBinary()
		if err != nil {
			return
		}
		setJSON(PQSignatureKeyPairResult{PublicKey: publicBytes, SecretKey: secretBytes})
		return
	}
	if len(op.Seed) != scheme.SeedSize() {
		return
	}
	publicKey, secretKey := scheme.DeriveKey(op.Seed)
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return
	}
	secretBytes, err := secretKey.MarshalBinary()
	if err != nil {
		return
	}
	setJSON(PQSignatureKeyPairResult{PublicKey: publicBytes, SecretKey: secretBytes})
}

//export circl_Cryptofuzz_OpPQSIG_Sign
func circl_Cryptofuzz_OpPQSIG_Sign(in []byte) {
	resetResult()

	var op OpPQSIG_Sign
	unmarshal(in, &op)
	scheme := pqSignatureScheme(op.PqSignatureType)
	if scheme == nil || len(op.Context) > 255 {
		return
	}
	if len(op.Context) != 0 && !scheme.SupportsContext() {
		return
	}
	secretKey, err := scheme.UnmarshalBinaryPrivateKey(op.SecretKey)
	if err != nil {
		return
	}
	if _, ok := slhSignatureID(op.PqSignatureType); ok {
		key, ok := secretKey.(slhdsa.PrivateKey)
		if !ok {
			return
		}
		var signature []byte
		if len(op.ExtraEntropy) == 0 {
			signature, err = slhdsa.SignDeterministic(&key, slhdsa.NewMessage(op.Message), op.Context)
		} else {
			entropySize := scheme.PublicKeySize() / 2
			if len(op.ExtraEntropy) != entropySize {
				return
			}
			signature, err = slhdsa.SignRandomized(
				&key,
				bytes.NewReader(op.ExtraEntropy),
				slhdsa.NewMessage(op.Message),
				op.Context,
			)
		}
		if err != nil {
			return
		}
		setResult(signature)
		return
	}
	if len(op.ExtraEntropy) != 0 {
		return
	}
	opts := &sign.SignatureOpts{Context: string(op.Context)}
	signature := scheme.Sign(secretKey, op.Message, opts)
	setResult(signature)
}

//export circl_Cryptofuzz_OpPQSIG_Verify
func circl_Cryptofuzz_OpPQSIG_Verify(in []byte) {
	resetResult()

	var op OpPQSIG_Verify
	unmarshal(in, &op)
	scheme := pqSignatureScheme(op.PqSignatureType)
	if scheme == nil {
		return
	}
	if len(op.Context) > 255 || (len(op.Context) != 0 && !scheme.SupportsContext()) {
		setJSON(false)
		return
	}
	publicKey, err := scheme.UnmarshalBinaryPublicKey(op.PublicKey)
	if err != nil {
		setJSON(false)
		return
	}
	if len(op.Signature) != scheme.SignatureSize() {
		setJSON(false)
		return
	}
	opts := &sign.SignatureOpts{Context: string(op.Context)}
	setJSON(scheme.Verify(publicKey, op.Message, op.Signature, opts))
}

func main() {}
