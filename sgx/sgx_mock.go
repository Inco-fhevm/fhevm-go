package sgx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
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
	Plaintext []byte
	Type      tfhe.FheUintType
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
	if sp.Type != tfhe.FheUint4 && sp.Type != tfhe.FheUint8 {
		panic(fmt.Sprintf("Expected FheUint4 or FheUint8, got %s", sp.Type))
	}

	return sp.Plaintext[0]
}

// AsUint16 returns the plaintext as a uint16.
func (sp SgxPlaintext) AsUint16() uint16 {
	if sp.Type != tfhe.FheUint16 {
		panic(fmt.Sprintf("Expected FheUint16, got %s", sp.Type))
	}

	return binary.BigEndian.Uint16(sp.Plaintext)
}

// AsUint32 returns the plaintext as a uint32.
func (sp SgxPlaintext) AsUint32() uint32 {
	if sp.Type != tfhe.FheUint32 {
		panic(fmt.Sprintf("Expected FheUint32, got %s", sp.Type))
	}

	return binary.BigEndian.Uint32(sp.Plaintext)
}

// AsUint64 returns the plaintext as a uint64.
func (sp SgxPlaintext) AsUint64() uint64 {
	if sp.Type != tfhe.FheUint64 {
		panic(fmt.Sprintf("expected FheUint64, got %s", sp.Type))
	}

	return binary.BigEndian.Uint64(sp.Plaintext)
}

func ToTfheCiphertext(sgxCt SgxPlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the SgxPlaintext struct as a byte array.
	// This will be used as the plaintext.
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(sgxCt)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	// Encrypt the plaintext using the public key.
	ciphertext, err := ecies.Encrypt(rand.Reader, &key.PublicKey, buf.Bytes(), nil, nil)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	hash := common.BytesToHash(crypto.Keccak256(ciphertext))
	return tfhe.TfheCiphertext{
		FheUintType:   sgxCt.Type,
		Serialization: ciphertext,
		Hash:          &hash,
	}, nil
}

func FromTfheCiphertext(ct *tfhe.TfheCiphertext) (SgxPlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintext, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return SgxPlaintext{}, err
	}

	// Decode the plaintext into a SgxPlaintext struct.
	buf := bytes.NewReader(plaintext)
	var sgxCt SgxPlaintext
	err = gob.NewDecoder(buf).Decode(&sgxCt)
	if err != nil {
		return SgxPlaintext{}, err
	}

	return sgxCt, nil
}
