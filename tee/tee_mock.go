package tee

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var key *ecies.PrivateKey

func init() {
	// For now, we hardcode the private key that will be used in the TEE.
	// We will change this to use a secure enclave key generation mechanism.
	hexKey := "4a3f9d7b12e8acef2f8a561e3c3b9f9dd3e8a3b1f4de4e8d243a45ad4b7e34cf"
	ecdsaKey, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		panic(err)
	}
	key = ecies.ImportECDSA(ecdsaKey)
}

type TeePlaintext struct {
	// Value is the bytes representation of the plaintext.
	Value []byte
	// Type is the type of the plaintext.
	FheUintType tfhe.FheUintType
	// Address is used as zkPoK on the TEE.
	Address common.Address
}

func NewTeePlaintext(plaintext []byte, fheType tfhe.FheUintType, address common.Address) TeePlaintext {
	return TeePlaintext{
		plaintext,
		fheType,
		address,
	}
}

// AsUint8 returns the plaintext as a uint8.
func (sp TeePlaintext) AsUint8() uint8 {
	if sp.FheUintType != tfhe.FheUint4 && sp.FheUintType != tfhe.FheUint8 {
		panic(fmt.Sprintf("Expected FheUint4 or FheUint8, got %s", sp.FheUintType))
	}

	return sp.Value[0]
}

// AsUint16 returns the plaintext as a uint16.
func (sp TeePlaintext) AsUint16() uint16 {
	if sp.FheUintType != tfhe.FheUint16 {
		panic(fmt.Sprintf("Expected FheUint16, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint16(sp.Value)
}

// AsUint32 returns the plaintext as a uint32.
func (sp TeePlaintext) AsUint32() uint32 {
	if sp.FheUintType != tfhe.FheUint32 {
		panic(fmt.Sprintf("Expected FheUint32, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint32(sp.Value)
}

// AsUint64 returns the plaintext as a uint64.
func (sp TeePlaintext) AsUint64() uint64 {
	if sp.FheUintType != tfhe.FheUint64 {
		panic(fmt.Sprintf("expected FheUint64, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint64(sp.Value)
}

func Encrypt(teeCt TeePlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the TeePlaintext struct as a byte array using JSON.
	// This will be used as the plaintext for the ECIES encryption.
	//
	// We only require that the implementation of this JSON is deterministic,
	// which is the case for golang's standard library.
	bz, err := json.Marshal(teeCt)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	// Encrypt the plaintext using the public key.
	ciphertext, err := ecies.Encrypt(rand.Reader, &key.PublicKey, bz, nil, nil)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	hash := common.BytesToHash(crypto.Keccak256(ciphertext))
	return tfhe.TfheCiphertext{
		FheUintType:   teeCt.FheUintType,
		Serialization: ciphertext,
		Hash:          &hash,
	}, nil
}

func Decrypt(ct *tfhe.TfheCiphertext) (TeePlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintextBz, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return TeePlaintext{}, err
	}

	// Decode the plaintext bytes into a TeePlaintext struct.
	var plaintext TeePlaintext
	err = json.Unmarshal(plaintextBz, &plaintext)
	if err != nil {
		return TeePlaintext{}, err
	}

	return plaintext, nil
}

// TODO:
// Need to be reviewed by Amaury and Elmer as we already have teeBitAndRun in tee_bit.go
// As I couldn't find BitOperator with 2 ciphertext in tee_bit.go, defining a new function here.
// Decrypt two ciphertexts in parameter and do bitAnd operation and then reencrypt it.
// Return a new ciphertext.
func BitAnd(lt *tfhe.TfheCiphertext, rt *tfhe.TfheCiphertext) (*tfhe.TfheCiphertext, error) {
	lp, err := Decrypt(lt)
	if err != nil {
		return nil, err
	}

	rp, err := Decrypt(rt)
	if err != nil {
		return nil, err
	}

	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()
	result := l & r

	// Re-encrypt
	resultBz := []byte{byte(result)}
	teePlaintext := NewTeePlaintext(resultBz, tfhe.FheUint8, common.Address{})
	ct, err := Encrypt(teePlaintext)
	if err != nil {
		return nil, err
	}

	return &ct, nil
}
