package tsgx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"testing"
)

// generate keys if not present
func setup() {
	if !AllGlobalKeysPresent() {
		fmt.Println("INFO: initializing global keys in tests")
		InitGlobalKeysWithNewKeys()
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

func TsgxEncryptDecrypt(t *testing.T, sgxUintType SgxUintType) {
	var val big.Int
	switch sgxUintType {
	case SgxBool:
		val.SetUint64(1)
	case SgxUint4:
		val.SetUint64(2)
	case SgxUint8:
		val.SetUint64(2)
	case SgxUint16:
		val.SetUint64(1337)
	case SgxUint32:
		val.SetUint64(1333337)
	case SgxUint64:
		val.SetUint64(13333377777777777)

	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct := new(TsgxCiphertext)
	ct.Encrypt(val, sgxUintType)
	res, err := ct.Decrypt()

	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if res.Cmp(&val) != 0 {
		t.Fatalf("Decryption result does not match the original value. Expected %s, got %s", val.Text(10), res.Text(10))
	}
}

func TsgxTrivialEncryptDecrypt(t *testing.T, sgxUintType SgxUintType) {
	var val big.Int
	switch sgxUintType {
	case SgxBool:
		val.SetUint64(1)
	case SgxUint4:
		val.SetUint64(2)
	case SgxUint8:
		val.SetUint64(2)
	case SgxUint16:
		val.SetUint64(1337)
	case SgxUint32:
		val.SetUint64(1333337)
	case SgxUint64:
		val.SetUint64(13333377777777777)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct := new(TsgxCiphertext)
	ct.TrivialEncrypt(val, sgxUintType)
	res, err := ct.Decrypt()
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if res.Cmp(&val) != 0 {
		t.Fatalf("Decryption result does not match the original value. Expected %s, got %s", val.Text(10), res.Text(10))
	}
}

func TsgxSerializeDeserialize(t *testing.T, sgxUintType SgxUintType) {
	var val big.Int
	switch sgxUintType {
	case SgxBool:
		val = *big.NewInt(1)
	case SgxUint4:
		val = *big.NewInt(2)
	case SgxUint8:
		val = *big.NewInt(2)
	case SgxUint16:
		val = *big.NewInt(1337)
	case SgxUint32:
		val = *big.NewInt(1333337)
	case SgxUint64:
		val = *big.NewInt(13333377777777777)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct1 := new(TsgxCiphertext)
	ct1.Encrypt(val, sgxUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TsgxCiphertext)
	err := ct2.Deserialize(ct1Ser, sgxUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}
}

func TsgxSerializeDeserializeCompact(t *testing.T, sgxUintType SgxUintType) {
	var val uint64
	switch sgxUintType {
	case SgxBool:
		val = 1
	case SgxUint4:
		val = 2
	case SgxUint8:
		val = 2
	case SgxUint16:
		val = 1337
	case SgxUint32:
		val = 1333337
	case SgxUint64:
		val = 13333377777777777
	case SgxUint160:
		val = 13333377777777777
	}

	ser := EncryptAndSerializeCompact(val, sgxUintType)
	ct1 := new(TsgxCiphertext)
	err := ct1.DeserializeCompact(ser, sgxUintType)
	if err != nil {
		t.Fatalf("ct1 compact deserialization failed")
	}
	ct1Ser := ct1.Serialize()

	ct2 := new(TsgxCiphertext)
	err = ct2.Deserialize(ct1Ser, sgxUintType)
	if err != nil {
		t.Fatalf("ct2 deserialization failed")
	}

	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}

	decrypted, err := ct2.Decrypt()
	if err != nil || uint64(decrypted.Uint64()) != val {
		t.Fatalf("decrypted value is incorrect")
	}
}

func TsgxTrivialSerializeDeserialize(t *testing.T, sgxUintType SgxUintType) {
	var val big.Int
	switch sgxUintType {
	case SgxBool:
		val = *big.NewInt(1)
	case SgxUint4:
		val = *big.NewInt(2)
	case SgxUint8:
		val = *big.NewInt(2)
	case SgxUint16:
		val = *big.NewInt(1337)
	case SgxUint32:
		val = *big.NewInt(1333337)
	case SgxUint64:
		val = *big.NewInt(13333377777777777)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct1 := new(TsgxCiphertext)
	ct1.TrivialEncrypt(val, sgxUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TsgxCiphertext)
	err := ct2.Deserialize(ct1Ser, sgxUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("trivial serialization is non-deterministic")
	}
}

func TsgxDeserializeFailure(t *testing.T, sgxUintType SgxUintType) {
	ct := new(TsgxCiphertext)
	input := make([]byte, 1)
	input[0] = 42
	err := ct.Deserialize(input, sgxUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TsgxDeserializeCompact(t *testing.T, sgxUintType SgxUintType) {
	var val uint64
	switch sgxUintType {
	case SgxBool:
		val = 1
	case SgxUint4:
		val = 2
	case SgxUint8:
		val = 2
	case SgxUint16:
		val = 1337
	case SgxUint32:
		val = 1333337
	case SgxUint64:
		val = 13333377777777777
	}

	ser := EncryptAndSerializeCompact(val, sgxUintType)
	ct := new(TsgxCiphertext)
	err := ct.DeserializeCompact(ser, sgxUintType)
	if err != nil {
		t.Fatalf("compact deserialization failed")
	}
	decryptedVal, err := ct.Decrypt()
	if err != nil || uint64(decryptedVal.Uint64()) != val {
		t.Fatalf("compact deserialization wrong decryption")
	}
}

func TsgxDeserializeCompactFailure(t *testing.T, sgxUintType SgxUintType) {
	ct := new(TsgxCiphertext)
	err := ct.DeserializeCompact(make([]byte, 10), sgxUintType)
	if err == nil {
		t.Fatalf("compact deserialization must have failed")
	}
}

func TsgxAdd(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Add(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarAdd(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarAdd(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxSub(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Sub(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarSub(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarSub(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxMul(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Mul(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarMul(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarMul(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarDiv(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case SgxUint8:
		a.SetUint64(4)
		b.SetUint64(2)
	case SgxUint16:
		a.SetUint64(49)
		b.SetUint64(144)
	case SgxUint32:
		a.SetUint64(70)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Div(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarDiv(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarRem(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case SgxUint8:
		a.SetUint64(4)
		b.SetUint64(2)
	case SgxUint16:
		a.SetUint64(49)
		b.SetUint64(144)
	case SgxUint32:
		a.SetUint64(70)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rem(&a, &b)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarRem(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxBitAnd(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxBool:
		a.SetUint64(1)
		b.SetUint64(1)
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() & b.Uint64()
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Bitand(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxBitOr(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() | b.Uint64()
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Bitor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxBitXor(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() ^ b.Uint64()
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Bitxor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxShl(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Shl(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarShl(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarShl(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxShr(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Shr(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxScalarShr(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarShr(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TsgxEq(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(2)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	case SgxUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue)
	}

	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 1
	} else {
		expected = 0
	}

	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Eq(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}

}

func TsgxScalarEq(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue)
	}
	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarEq(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxNe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(2)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	case SgxUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetUint64(8888)
	}

	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 0
	} else {
		expected = 1
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes, _ := ctA.Ne(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxScalarNe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case SgxUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	case SgxUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetUint64(8888)
	}

	var expected uint64
	// No != for big.Int
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 0
	} else {
		expected = 1
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes, _ := ctA.ScalarNe(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TsgxGe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Ge(ctB)
	ctRes2, _ := ctB.Ge(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 1, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TsgxScalarGe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarGe(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxGt(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Gt(ctB)
	ctRes2, _ := ctB.Gt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TsgxScalarGt(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarGt(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxLe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Le(ctB)
	ctRes2, _ := ctB.Le(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TsgxScalarLe(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarLe(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxLt(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Lt(ctB)
	ctRes2, _ := ctB.Lt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TsgxScalarLt(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarLt(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxMin(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Min(ctB)
	ctRes2, _ := ctB.Min(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TsgxScalarMin(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarMin(&b)
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxMax(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctA.Max(ctB)
	ctRes2, _ := ctB.Max(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TsgxScalarMax(t *testing.T, sgxUintType SgxUintType) {
	var a, b big.Int
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.ScalarMax(&b)
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TsgxNeg(t *testing.T, sgxUintType SgxUintType) {
	var a big.Int
	var expected uint64

	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		expected = uint64(uint8(16 - a.Uint64()))
	case SgxUint8:
		a.SetUint64(2)
		expected = uint64(-uint8(a.Uint64()))
	case SgxUint16:
		a.SetUint64(4283)
		expected = uint64(-uint16(a.Uint64()))
	case SgxUint32:
		a.SetUint64(1333337)
		expected = uint64(-uint32(a.Uint64()))
	case SgxUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(-uint64(a.Uint64()))
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctRes1, _ := ctA.Neg()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TsgxNot(t *testing.T, sgxUintType SgxUintType) {
	var a big.Int
	var expected uint64
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		expected = uint64(^uint8(a.Uint64()))
	case SgxUint8:
		a.SetUint64(2)
		expected = uint64(^uint8(a.Uint64()))
	case SgxUint16:
		a.SetUint64(4283)
		expected = uint64(^uint16(a.Uint64()))
	case SgxUint32:
		a.SetUint64(1333337)
		expected = uint64(^uint32(a.Uint64()))
	case SgxUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(^uint64(a.Uint64()))
	}
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)

	ctRes1, _ := ctA.Not()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TsgxIfThenElse(t *testing.T, sgxUintType SgxUintType) {
	var condition, condition2, a, b big.Int
	condition.SetUint64(1)
	condition2.SetUint64(0)
	switch sgxUintType {
	case SgxUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case SgxUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case SgxUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337)
	}
	ctCondition := new(TsgxCiphertext)
	ctCondition.Encrypt(condition, SgxBool)
	ctCondition2 := new(TsgxCiphertext)
	ctCondition2.Encrypt(condition2, SgxBool)
	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintType)
	ctB := new(TsgxCiphertext)
	ctB.Encrypt(b, sgxUintType)
	ctRes1, _ := ctCondition.IfThenElse(ctA, ctB)
	ctRes2, _ := ctCondition2.IfThenElse(ctA, ctB)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TsgxCast(t *testing.T, sgxUintTypeFrom SgxUintType, sgxUintTypeTo SgxUintType) {
	var a big.Int
	switch sgxUintTypeFrom {
	case SgxUint4:
		a.SetUint64(2)
	case SgxUint8:
		a.SetUint64(2)
	case SgxUint16:
		a.SetUint64(4283)
	case SgxUint32:
		a.SetUint64(1333337)
	case SgxUint64:
		a.SetUint64(13333377777777777)
	}

	var modulus uint64
	switch sgxUintTypeTo {
	case SgxUint4:
		modulus = uint64(math.Pow(2, 4))
	case SgxUint8:
		modulus = uint64(math.Pow(2, 8))
	case SgxUint16:
		modulus = uint64(math.Pow(2, 16))
	case SgxUint32:
		modulus = uint64(math.Pow(2, 32))
	case SgxUint64:
		modulus = uint64(math.Pow(2, 64))
	}

	ctA := new(TsgxCiphertext)
	ctA.Encrypt(a, sgxUintTypeFrom)
	ctRes, err := ctA.CastTo(sgxUintTypeTo)
	if err != nil {
		t.Fatal(err)
	}

	if ctRes.SgxUintType != sgxUintTypeTo {
		t.Fatalf("type %d != type %d", ctA.SgxUintType, sgxUintTypeTo)
	}
	res, err := ctRes.Decrypt()
	expected := a.Uint64() % modulus
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", res.Uint64(), expected)
	}
}

func TestTsgxEncryptDecryptBool(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxBool)
}

func TestTsgxEncryptDecrypt4(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint4)
}

func TestTsgxEncryptDecrypt8(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint8)
}

func TestTsgxEncryptDecrypt16(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint16)
}

func TestTsgxEncryptDecrypt32(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint32)
}

func TestTsgxEncryptDecrypt64(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint64)
}

func TestTsgxEncryptDecrypt160(t *testing.T) {
	TsgxEncryptDecrypt(t, SgxUint160)
}

func TestTsgxTrivialEncryptDecryptBool(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxBool)
}

func TestTsgxTrivialEncryptDecrypt4(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint4)
}

func TestTsgxTrivialEncryptDecrypt8(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint8)
}

func TestTsgxTrivialEncryptDecrypt16(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint16)
}

func TestTsgxTrivialEncryptDecrypt32(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint32)
}

func TestTsgxTrivialEncryptDecrypt64(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint64)
}

func TestTsgxTrivialEncryptDecrypt160(t *testing.T) {
	TsgxTrivialEncryptDecrypt(t, SgxUint160)
}

func TestTsgxSerializeDeserializeBool(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxBool)
}

func TestTsgxSerializeDeserialize4(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint4)
}

func TestTsgxSerializeDeserialize8(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint8)
}

func TestTsgxSerializeDeserialize16(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint16)
}

func TestTsgxSerializeDeserialize32(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint32)
}

func TestTsgxSerializeDeserialize64(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint64)
}

func TestTsgxSerializeDeserialize160(t *testing.T) {
	TsgxSerializeDeserialize(t, SgxUint160)
}

func TestTsgxSerializeDeserializeCompactBool(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxBool)
}

func TestTsgxSerializeDeserializeCompact4(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxUint4)
}

func TestTsgxSerializeDeserializeCompact16(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxUint16)
}

func TestTsgxSerializeDeserializeCompact32(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxUint32)
}

func TestTsgxSerializeDeserializeCompact64(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxUint64)
}

func TestTsgxSerializeDeserializeCompact160(t *testing.T) {
	TsgxSerializeDeserializeCompact(t, SgxUint160)
}

func TestTsgxTrivialSerializeDeserializeBool(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxBool)
}

func TestTsgxTrivialSerializeDeserialize4(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint4)
}

func TestTsgxTrivialSerializeDeserialize8(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint8)
}

func TestTsgxTrivialSerializeDeserialize16(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint16)
}

func TestTsgxTrivialSerializeDeserialize32(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint32)
}

func TestTsgxTrivialSerializeDeserialize64(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint64)
}

func TestTsgxTrivialSerializeDeserialize160(t *testing.T) {
	TsgxTrivialSerializeDeserialize(t, SgxUint160)
}

func TestTsgxDeserializeFailureBool(t *testing.T) {
	TsgxDeserializeFailure(t, SgxBool)
}

func TestTsgxDeserializeFailure4(t *testing.T) {
	TsgxDeserializeFailure(t, SgxUint4)
}

func TestTsgxDeserializeFailure8(t *testing.T) {
	TsgxDeserializeFailure(t, SgxUint8)
}

func TestTsgxDeserializeFailure16(t *testing.T) {
	TsgxDeserializeFailure(t, SgxUint16)
}

func TestTsgxDeserializeFailure32(t *testing.T) {
	TsgxDeserializeFailure(t, SgxUint32)
}

func TestTsgxDeserializeFailure64(t *testing.T) {
	TsgxDeserializeFailure(t, SgxUint64)
}

func TestTsgxDeserializeCompactBool(t *testing.T) {
	TsgxDeserializeCompact(t, SgxBool)
}

func TestTsgxDeserializeCompact4(t *testing.T) {
	TsgxDeserializeCompact(t, SgxUint4)
}

func TestTsgxDeserializeCompact8(t *testing.T) {
	TsgxDeserializeCompact(t, SgxUint8)
}

func TestTsgxDeserializeCompact16(t *testing.T) {
	TsgxDeserializeCompact(t, SgxUint16)
}

func TestTsgxDeserializeCompact32(t *testing.T) {
	TsgxDeserializeCompact(t, SgxUint32)
}

func TestTsgxDeserializeCompact64(t *testing.T) {
	TsgxDeserializeCompact(t, SgxUint64)
}

func TestTsgxDeserializeCompactFailureBool(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxBool)
}

func TestTsgxDeserializeCompactFailure4(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxUint4)
}

func TestTsgxDeserializeCompactFailure8(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxUint8)
}

func TestTsgxDeserializeCompactFailure16(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxUint16)
}

func TestTsgxDeserializeCompatcFailure32(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxUint32)
}

func TestTsgxDeserializeCompatcFailure64(t *testing.T) {
	TsgxDeserializeCompactFailure(t, SgxUint64)
}

func TestTsgxAdd4(t *testing.T) {
	TsgxAdd(t, SgxUint4)
}

func TestTsgxAdd8(t *testing.T) {
	TsgxAdd(t, SgxUint8)
}

func TestTsgxAdd16(t *testing.T) {
	TsgxAdd(t, SgxUint16)
}

func TestTsgxAdd32(t *testing.T) {
	TsgxAdd(t, SgxUint32)
}

func TestTsgxAdd64(t *testing.T) {
	TsgxAdd(t, SgxUint64)
}

func TestTsgxScalarAdd4(t *testing.T) {
	TsgxScalarAdd(t, SgxUint4)
}

func TestTsgxScalarAdd8(t *testing.T) {
	TsgxScalarAdd(t, SgxUint8)
}

func TestTsgxScalarAdd16(t *testing.T) {
	TsgxScalarAdd(t, SgxUint16)
}

func TestTsgxScalarAdd32(t *testing.T) {
	TsgxScalarAdd(t, SgxUint32)
}

func TestTsgxScalarAdd64(t *testing.T) {
	TsgxScalarAdd(t, SgxUint32)
}

func TestTsgxSub4(t *testing.T) {
	TsgxSub(t, SgxUint4)
}

func TestTsgxSub8(t *testing.T) {
	TsgxSub(t, SgxUint8)
}

func TestTsgxSub16(t *testing.T) {
	TsgxSub(t, SgxUint16)
}

func TestTsgxSub32(t *testing.T) {
	TsgxSub(t, SgxUint32)
}

func TestTsgxSub64(t *testing.T) {
	TsgxSub(t, SgxUint64)
}

func TestTsgxScalarSub4(t *testing.T) {
	TsgxScalarSub(t, SgxUint4)
}

func TestTsgxScalarSub8(t *testing.T) {
	TsgxScalarSub(t, SgxUint8)
}

func TestTsgxScalarSub16(t *testing.T) {
	TsgxScalarSub(t, SgxUint16)
}

func TestTsgxScalarSub32(t *testing.T) {
	TsgxScalarSub(t, SgxUint32)
}

func TestTsgxScalarSub64(t *testing.T) {
	TsgxScalarSub(t, SgxUint64)
}

func TestTsgxMul4(t *testing.T) {
	TsgxMul(t, SgxUint4)
}

func TestTsgxMul8(t *testing.T) {
	TsgxMul(t, SgxUint8)
}

func TestTsgxMul16(t *testing.T) {
	TsgxMul(t, SgxUint16)
}

func TestTsgxMul32(t *testing.T) {
	TsgxMul(t, SgxUint32)
}

func TestTsgxMul64(t *testing.T) {
	TsgxMul(t, SgxUint64)
}

func TestTsgxScalarMul4(t *testing.T) {
	TsgxScalarMul(t, SgxUint4)
}

func TestTsgxScalarMul8(t *testing.T) {
	TsgxScalarMul(t, SgxUint8)
}

func TestTsgxScalarMul16(t *testing.T) {
	TsgxScalarMul(t, SgxUint16)
}

func TestTsgxScalarMul32(t *testing.T) {
	TsgxScalarMul(t, SgxUint32)
}

func TestTsgxScalarMul64(t *testing.T) {
	TsgxScalarMul(t, SgxUint64)
}

func TestTsgxScalarDiv4(t *testing.T) {
	TsgxScalarDiv(t, SgxUint4)
}

func TestTsgxScalarDiv8(t *testing.T) {
	TsgxScalarDiv(t, SgxUint8)
}

func TestTsgxScalarDiv16(t *testing.T) {
	TsgxScalarDiv(t, SgxUint16)
}

func TestTsgxScalarDiv32(t *testing.T) {
	TsgxScalarDiv(t, SgxUint32)
}

func TestTsgxScalarDiv64(t *testing.T) {
	TsgxScalarDiv(t, SgxUint64)
}

func TestTsgxScalarRem4(t *testing.T) {
	TsgxScalarRem(t, SgxUint4)
}

func TestTsgxScalarRem8(t *testing.T) {
	TsgxScalarRem(t, SgxUint8)
}

func TestTsgxScalarRem16(t *testing.T) {
	TsgxScalarRem(t, SgxUint16)
}

func TestTsgxScalarRem32(t *testing.T) {
	TsgxScalarRem(t, SgxUint32)
}

func TestTsgxScalarRem64(t *testing.T) {
	TsgxScalarRem(t, SgxUint64)
}

func TestTsgxBitAnd4(t *testing.T) {
	TsgxBitAnd(t, SgxUint4)
}

func TestTsgxBitAnd8(t *testing.T) {
	TsgxBitAnd(t, SgxUint8)
}

func TestTsgxBitAnd16(t *testing.T) {
	TsgxBitAnd(t, SgxUint16)
}

func TestTsgxBitAnd32(t *testing.T) {
	TsgxBitAnd(t, SgxUint32)
}

func TestTsgxBitAnd64(t *testing.T) {
	TsgxBitAnd(t, SgxUint64)
}

func TestTsgxBitOr4(t *testing.T) {
	TsgxBitOr(t, SgxUint4)
}

func TestTsgxBitOr8(t *testing.T) {
	TsgxBitOr(t, SgxUint8)
}

func TestTsgxBitOr16(t *testing.T) {
	TsgxBitOr(t, SgxUint16)
}

func TestTsgxBitOr32(t *testing.T) {
	TsgxBitOr(t, SgxUint32)
}

func TestTsgxBitOr64(t *testing.T) {
	TsgxBitOr(t, SgxUint64)
}

func TestTsgxBitXor4(t *testing.T) {
	TsgxBitXor(t, SgxUint4)
}

func TestTsgxBitXor8(t *testing.T) {
	TsgxBitXor(t, SgxUint8)
}

func TestTsgxBitXor16(t *testing.T) {
	TsgxBitXor(t, SgxUint16)
}

func TestTsgxBitXor32(t *testing.T) {
	TsgxBitXor(t, SgxUint32)
}

func TestTsgxBitXor64(t *testing.T) {
	TsgxBitXor(t, SgxUint64)
}

func TestTsgxShl4(t *testing.T) {
	TsgxShl(t, SgxUint4)
}

func TestTsgxShl8(t *testing.T) {
	TsgxShl(t, SgxUint8)
}

func TestTsgxShl16(t *testing.T) {
	TsgxShl(t, SgxUint16)
}

func TestTsgxShl32(t *testing.T) {
	TsgxShl(t, SgxUint32)
}

func TestTsgxShl64(t *testing.T) {
	TsgxShl(t, SgxUint64)
}

func TestTsgxScalarShl4(t *testing.T) {
	TsgxScalarShl(t, SgxUint4)
}

func TestTsgxScalarShl8(t *testing.T) {
	TsgxScalarShl(t, SgxUint8)
}

func TestTsgxScalarShl16(t *testing.T) {
	TsgxScalarShl(t, SgxUint16)
}

func TestTsgxScalarShl32(t *testing.T) {
	TsgxScalarShl(t, SgxUint32)
}

func TestTsgxScalarShl64(t *testing.T) {
	TsgxScalarShl(t, SgxUint64)
}

func TestTsgxShr4(t *testing.T) {
	TsgxShr(t, SgxUint4)
}

func TestTsgxShr8(t *testing.T) {
	TsgxShr(t, SgxUint8)
}

func TestTsgxShr16(t *testing.T) {
	TsgxShr(t, SgxUint16)
}

func TestTsgxShr32(t *testing.T) {
	TsgxShr(t, SgxUint32)
}

func TestTsgxShr64(t *testing.T) {
	TsgxShr(t, SgxUint64)
}

func TestTsgxScalarShr8(t *testing.T) {
	TsgxScalarShr(t, SgxUint8)
}

func TestTsgxScalarShr16(t *testing.T) {
	TsgxScalarShr(t, SgxUint16)
}

func TestTsgxScalarShr32(t *testing.T) {
	TsgxScalarShr(t, SgxUint32)
}

func TestTsgxScalarShr64(t *testing.T) {
	TsgxScalarShr(t, SgxUint64)
}

func TestTsgxEq4(t *testing.T) {
	TsgxEq(t, SgxUint4)
}

func TestTsgxEq8(t *testing.T) {
	TsgxEq(t, SgxUint8)
}

func TestTsgxEq16(t *testing.T) {
	TsgxEq(t, SgxUint16)
}

func TestTsgxEq32(t *testing.T) {
	TsgxEq(t, SgxUint32)
}

func TestTsgxEq64(t *testing.T) {
	TsgxEq(t, SgxUint64)
}

func TestTsgxEq160(t *testing.T) {
	TsgxEq(t, SgxUint160)
}

func TestTsgxScalarEq4(t *testing.T) {
	TsgxScalarEq(t, SgxUint4)
}

func TestTsgxScalarEq8(t *testing.T) {
	TsgxScalarEq(t, SgxUint8)
}

func TestTsgxScalarEq16(t *testing.T) {
	TsgxScalarEq(t, SgxUint16)
}

func TestTsgxScalarEq32(t *testing.T) {
	TsgxScalarEq(t, SgxUint32)
}

func TestTsgxScalarEq64(t *testing.T) {
	TsgxScalarEq(t, SgxUint64)
}

func TestTsgxScalarEq160(t *testing.T) {
	TsgxScalarEq(t, SgxUint160)
}

func TestTsgxNe4(t *testing.T) {
	TsgxNe(t, SgxUint8)
}

func TestTsgxNe8(t *testing.T) {
	TsgxNe(t, SgxUint8)
}

func TestTsgxNe16(t *testing.T) {
	TsgxNe(t, SgxUint16)
}

func TestTsgxNe32(t *testing.T) {
	TsgxNe(t, SgxUint32)
}

func TestTsgxNe64(t *testing.T) {
	TsgxNe(t, SgxUint64)
}

func TestTsgxNe160(t *testing.T) {
	TsgxNe(t, SgxUint160)
}

func TestTsgxScalarNe4(t *testing.T) {
	TsgxScalarNe(t, SgxUint4)
}

func TestTsgxScalarNe8(t *testing.T) {
	TsgxScalarNe(t, SgxUint8)
}

func TestTsgxScalarNe16(t *testing.T) {
	TsgxScalarNe(t, SgxUint16)
}

func TestTsgxScalarNe32(t *testing.T) {
	TsgxScalarNe(t, SgxUint32)
}

func TestTsgxScalarNe64(t *testing.T) {
	TsgxScalarNe(t, SgxUint64)
}

func TestTsgxScalarNe160(t *testing.T) {
	TsgxScalarNe(t, SgxUint160)
}

func TestTsgxGe4(t *testing.T) {
	TsgxGe(t, SgxUint4)
}

func TestTsgxGe8(t *testing.T) {
	TsgxGe(t, SgxUint8)
}

func TestTsgxGe16(t *testing.T) {
	TsgxGe(t, SgxUint16)
}

func TestTsgxGe32(t *testing.T) {
	TsgxGe(t, SgxUint32)
}

func TestTsgxGe64(t *testing.T) {
	TsgxGe(t, SgxUint64)
}

func TestTsgxScalarGe4(t *testing.T) {
	TsgxScalarGe(t, SgxUint4)
}

func TestTsgxScalarGe8(t *testing.T) {
	TsgxScalarGe(t, SgxUint8)
}

func TestTsgxScalarGe16(t *testing.T) {
	TsgxScalarGe(t, SgxUint16)
}

func TestTsgxScalarGe32(t *testing.T) {
	TsgxScalarGe(t, SgxUint32)
}

func TestTsgxScalarGe64(t *testing.T) {
	TsgxScalarGe(t, SgxUint64)
}

func TestTsgxGt4(t *testing.T) {
	TsgxGt(t, SgxUint4)
}

func TestTsgxGt8(t *testing.T) {
	TsgxGt(t, SgxUint8)
}

func TestTsgxGt16(t *testing.T) {
	TsgxGt(t, SgxUint16)
}

func TestTsgxGt32(t *testing.T) {
	TsgxGt(t, SgxUint32)
}

func TestTsgxGt64(t *testing.T) {
	TsgxGt(t, SgxUint64)
}

func TestTsgxScalarGt4(t *testing.T) {
	TsgxScalarGt(t, SgxUint4)
}

func TestTsgxScalarGt8(t *testing.T) {
	TsgxScalarGt(t, SgxUint8)
}

func TestTsgxScalarGt16(t *testing.T) {
	TsgxScalarGt(t, SgxUint16)
}

func TestTsgxScalarGt32(t *testing.T) {
	TsgxScalarGt(t, SgxUint32)
}

func TestTsgxScalarGt64(t *testing.T) {
	TsgxScalarGt(t, SgxUint64)
}

func TestTsgxLe4(t *testing.T) {
	TsgxLe(t, SgxUint4)
}

func TestTsgxLe8(t *testing.T) {
	TsgxLe(t, SgxUint8)
}

func TestTsgxLe16(t *testing.T) {
	TsgxLe(t, SgxUint16)
}

func TestTsgxLe32(t *testing.T) {
	TsgxLe(t, SgxUint32)
}

func TestTsgxLe64(t *testing.T) {
	TsgxLe(t, SgxUint64)
}

func TestTsgxScalarLe4(t *testing.T) {
	TsgxScalarLe(t, SgxUint4)
}

func TestTsgxScalarLe8(t *testing.T) {
	TsgxScalarLe(t, SgxUint8)
}

func TestTsgxScalarLe16(t *testing.T) {
	TsgxScalarLe(t, SgxUint16)
}

func TestTsgxScalarLe32(t *testing.T) {
	TsgxScalarLe(t, SgxUint32)
}

func TestTsgxScalarLe64(t *testing.T) {
	TsgxScalarLe(t, SgxUint64)
}

func TestTsgxLt4(t *testing.T) {
	TsgxLt(t, SgxUint4)
}

func TestTsgxLt8(t *testing.T) {
	TsgxLt(t, SgxUint8)
}

func TestTsgxLt16(t *testing.T) {
	TsgxLt(t, SgxUint16)
}
func TestTsgxLt32(t *testing.T) {
	TsgxLt(t, SgxUint32)
}
func TestTsgxLt64(t *testing.T) {
	TsgxLt(t, SgxUint64)
}

func TestTsgxScalarLt4(t *testing.T) {
	TsgxScalarLt(t, SgxUint4)
}

func TestTsgxScalarLt8(t *testing.T) {
	TsgxScalarLt(t, SgxUint8)
}

func TestTsgxScalarLt16(t *testing.T) {
	TsgxScalarLt(t, SgxUint16)
}

func TestTsgxScalarLt32(t *testing.T) {
	TsgxScalarLt(t, SgxUint32)
}

func TestTsgxScalarLt64(t *testing.T) {
	TsgxScalarLt(t, SgxUint64)
}

func TestTsgxMin4(t *testing.T) {
	TsgxMin(t, SgxUint4)
}

func TestTsgxMin8(t *testing.T) {
	TsgxMin(t, SgxUint8)
}

func TestTsgxMin16(t *testing.T) {
	TsgxMin(t, SgxUint16)
}
func TestTsgxMin32(t *testing.T) {
	TsgxMin(t, SgxUint32)
}
func TestTsgxMin64(t *testing.T) {
	TsgxMin(t, SgxUint64)
}

func TestTsgxScalarMin4(t *testing.T) {
	TsgxScalarMin(t, SgxUint4)
}

func TestTsgxScalarMin8(t *testing.T) {
	TsgxScalarMin(t, SgxUint8)
}

func TestTsgxScalarMin16(t *testing.T) {
	TsgxScalarMin(t, SgxUint16)
}

func TestTsgxScalarMin32(t *testing.T) {
	TsgxScalarMin(t, SgxUint32)
}

func TestTsgxScalarMin64(t *testing.T) {
	TsgxScalarMin(t, SgxUint64)
}

func TestTsgxMax4(t *testing.T) {
	TsgxMax(t, SgxUint4)
}

func TestTsgxMax8(t *testing.T) {
	TsgxMax(t, SgxUint8)
}

func TestTsgxMax16(t *testing.T) {
	TsgxMax(t, SgxUint16)
}
func TestTsgxMax32(t *testing.T) {
	TsgxMax(t, SgxUint32)
}
func TestTsgxMax64(t *testing.T) {
	TsgxMax(t, SgxUint64)
}

func TestTsgxScalarMax4(t *testing.T) {
	TsgxScalarMax(t, SgxUint4)
}

func TestTsgxScalarMax8(t *testing.T) {
	TsgxScalarMax(t, SgxUint8)
}

func TestTsgxScalarMax16(t *testing.T) {
	TsgxScalarMax(t, SgxUint16)
}

func TestTsgxScalarMax32(t *testing.T) {
	TsgxScalarMax(t, SgxUint32)
}

func TestTsgxScalarMax64(t *testing.T) {
	TsgxScalarMax(t, SgxUint64)
}

func TestTsgxNeg4(t *testing.T) {
	TsgxNeg(t, SgxUint4)
}

func TestTsgxNeg8(t *testing.T) {
	TsgxNeg(t, SgxUint8)
}

func TestTsgxNeg16(t *testing.T) {
	TsgxNeg(t, SgxUint16)
}
func TestTsgxNeg32(t *testing.T) {
	TsgxNeg(t, SgxUint32)
}
func TestTsgxNeg64(t *testing.T) {
	TsgxNeg(t, SgxUint64)
}

func TestTsgxNot4(t *testing.T) {
	TsgxNot(t, SgxUint8)
}

func TestTsgxNot8(t *testing.T) {
	TsgxNot(t, SgxUint8)
}

func TestTsgxNot16(t *testing.T) {
	TsgxNot(t, SgxUint16)
}
func TestTsgxNot32(t *testing.T) {
	TsgxNot(t, SgxUint32)
}
func TestTsgxNot64(t *testing.T) {
	TsgxNot(t, SgxUint64)
}

func TestTsgxIfThenElse4(t *testing.T) {
	TsgxIfThenElse(t, SgxUint4)
}

func TestTsgxIfThenElse8(t *testing.T) {
	TsgxIfThenElse(t, SgxUint8)
}

func TestTsgxIfThenElse16(t *testing.T) {
	TsgxIfThenElse(t, SgxUint16)
}
func TestTsgxIfThenElse32(t *testing.T) {
	TsgxIfThenElse(t, SgxUint32)
}
func TestTsgxIfThenElse64(t *testing.T) {
	TsgxIfThenElse(t, SgxUint64)
}

func TestTsgx4Cast8(t *testing.T) {
	TsgxCast(t, SgxUint4, SgxUint8)
}

func TestTsgx4Cast16(t *testing.T) {
	TsgxCast(t, SgxUint4, SgxUint16)
}

func TestTsgx4Cast32(t *testing.T) {
	TsgxCast(t, SgxUint4, SgxUint32)
}

func TestTsgx4Cast64(t *testing.T) {
	TsgxCast(t, SgxUint4, SgxUint64)
}

func TestTsgx8Cast4(t *testing.T) {
	TsgxCast(t, SgxUint8, SgxUint4)
}

func TestTsgx8Cast16(t *testing.T) {
	TsgxCast(t, SgxUint4, SgxUint16)
}

func TestTsgx8Cast32(t *testing.T) {
	TsgxCast(t, SgxUint8, SgxUint32)
}

func TestTsgx8Cast64(t *testing.T) {
	TsgxCast(t, SgxUint8, SgxUint64)
}

func TestTsgx16Cast4(t *testing.T) {
	TsgxCast(t, SgxUint16, SgxUint4)
}

func TestTsgx16Cast8(t *testing.T) {
	TsgxCast(t, SgxUint16, SgxUint8)
}

func TestTsgx16Cast32(t *testing.T) {
	TsgxCast(t, SgxUint16, SgxUint32)
}

func TestTsgx16Cast64(t *testing.T) {
	TsgxCast(t, SgxUint16, SgxUint64)
}

func TestTsgx32Cast4(t *testing.T) {
	TsgxCast(t, SgxUint32, SgxUint4)
}

func TestTsgx32Cast8(t *testing.T) {
	TsgxCast(t, SgxUint32, SgxUint8)
}

func TestTsgx32Cast16(t *testing.T) {
	TsgxCast(t, SgxUint32, SgxUint16)
}

func TestTsgx32Cast64(t *testing.T) {
	TsgxCast(t, SgxUint32, SgxUint64)
}

func TestTsgx64Cast4(t *testing.T) {
	TsgxCast(t, SgxUint64, SgxUint4)
}

func TestTsgx64Cast8(t *testing.T) {
	TsgxCast(t, SgxUint64, SgxUint8)
}

func TestTsgx64Cast16(t *testing.T) {
	TsgxCast(t, SgxUint64, SgxUint16)
}

func TestTsgx64Cast32(t *testing.T) {
	TsgxCast(t, SgxUint64, SgxUint32)
}
