package sgx

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var key *ecies.PrivateKey

func init() {
	// For now, we hardcode the private key that will be used in the SGX.
	// We will change this to use a secure enclave key generation mechanism.
	hexKey := "4a3f9d7b12e8acef2f8a561e3c3b9f9dd3e8a3b1f4de4e8d243a45ad4b7e34cf"
	ecdsaKey, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		panic(err)
	}
	key = ecies.ImportECDSA(ecdsaKey)
}

type SgxPlaintext struct {
	// Value is the bytes representation of the plaintext.
	Value []byte
	// Type is the type of the plaintext.
	FheUintType tfhe.FheUintType
	// Address is used as zkPoK on the SGX.
	Address common.Address
}

func NewSgxPlaintext(plaintext []byte, fheType tfhe.FheUintType, address common.Address) SgxPlaintext {
	return SgxPlaintext{
		plaintext,
		fheType,
		address,
	}
}

// AsUint8 returns the plaintext as a uint8.
func (sp SgxPlaintext) AsUint8() uint8 {
	if sp.FheUintType != tfhe.FheUint4 && sp.FheUintType != tfhe.FheUint8 {
		panic(fmt.Sprintf("Expected FheUint4 or FheUint8, got %s", sp.FheUintType))
	}

	return sp.Value[0]
}

// AsUint16 returns the plaintext as a uint16.
func (sp SgxPlaintext) AsUint16() uint16 {
	if sp.FheUintType != tfhe.FheUint16 {
		panic(fmt.Sprintf("Expected FheUint16, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint16(sp.Value)
}

// AsUint32 returns the plaintext as a uint32.
func (sp SgxPlaintext) AsUint32() uint32 {
	if sp.FheUintType != tfhe.FheUint32 {
		panic(fmt.Sprintf("Expected FheUint32, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint32(sp.Value)
}

// AsUint64 returns the plaintext as a uint64.
func (sp SgxPlaintext) AsUint64() uint64 {
	if sp.FheUintType != tfhe.FheUint64 {
		panic(fmt.Sprintf("expected FheUint64, got %s", sp.FheUintType))
	}

	return binary.BigEndian.Uint64(sp.Value)
}

func Encrypt(sgxCt SgxPlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the SgxPlaintext struct as a byte array using JSON.
	// This will be used as the plaintext for the ECIES encryption.
	//
	// We only require that the implementation of this JSON is deterministic,
	// which is the case for golang's standard library.
	bz, err := json.Marshal(sgxCt)
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
		FheUintType:   sgxCt.FheUintType,
		Serialization: ciphertext,
		Hash:          &hash,
	}, nil
}

func Decrypt(ct *tfhe.TfheCiphertext) (SgxPlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintextBz, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return SgxPlaintext{}, err
	}

	// Decode the plaintext bytes into a SgxPlaintext struct.
	var plaintext SgxPlaintext
	err = json.Unmarshal(plaintextBz, &plaintext)
	if err != nil {
		return SgxPlaintext{}, err
	}

	return plaintext, nil
}
