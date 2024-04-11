package sgx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var key *ecies.PrivateKey

func init() {
	// For now, we hardcode the private key that will be used in the SGX.
	// We will change this to use a secure enclave key generation mechanism.
	hexKey := "0x...."
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

func ToTfheCiphertext(sgxCt SgxPlaintext) (tfhe.TfheCiphertext, error) {
	// Encode the SgxPlaintext struct as a byte array.
	// This will be used as the plaintext.
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, sgxCt)
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

func FromTfheCiphertext(ct tfhe.TfheCiphertext) (SgxPlaintext, error) {
	// Decrypt the ciphertext using the private key.
	plaintext, err := key.Decrypt(ct.Serialization, nil, nil)
	if err != nil {
		return SgxPlaintext{}, err
	}

	// Decode the plaintext into a SgxPlaintext struct.
	buf := bytes.NewReader(plaintext)
	var sgxCt SgxPlaintext
	err = binary.Read(buf, binary.BigEndian, &sgxCt)
	if err != nil {
		return SgxPlaintext{}, err
	}

	return sgxCt, nil
}
