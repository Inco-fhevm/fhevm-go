package tsgx

/*
#include "tsgx_wrappers.h"
*/
import "C"

import (
	"fmt"
	"math/big"
	"os"
	"path"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Expanded TSGX ciphertext sizes by type, in bytes.
var ExpandedSgxCiphertextSize map[SgxUintType]uint

func GetExpandedSgxCiphertextSize(t SgxUintType) (size uint, found bool) {
	size, found = ExpandedSgxCiphertextSize[t]
	return
}

// Compact TSGX ciphertext sizes by type, in bytes.
var compactSgxCiphertextSize map[SgxUintType]uint

func GetCompactSgxCiphertextSize(t SgxUintType) (size uint, found bool) {
	size, found = compactSgxCiphertextSize[t]
	return
}

// server key: evaluation key
var sks unsafe.Pointer

// client key: secret key
var cks unsafe.Pointer

// public key
var pks unsafe.Pointer
var pksHash common.Hash

// Get public key hash
func GetPksHash() common.Hash {
	return pksHash
}

// Generate keys for the sgxvm (sks, cks, psk)
func generateSgxvmKeys() (unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) {
	var keys = C.generate_sgxvm_keys()
	return keys.sks, keys.cks, keys.pks
}

func AllGlobalKeysPresent() bool {
	return sks != nil && cks != nil && pks != nil
}

func InitGlobalKeysWithNewKeys() {
	sks, cks, pks = generateSgxvmKeys()
	initCiphertextSizes()
}

func initCiphertextSizes() {
	ExpandedSgxCiphertextSize = make(map[SgxUintType]uint)
	compactSgxCiphertextSize = make(map[SgxUintType]uint)

	ExpandedSgxCiphertextSize[SgxBool] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxBool).Serialize()))
	ExpandedSgxCiphertextSize[SgxUint4] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxUint4).Serialize()))
	ExpandedSgxCiphertextSize[SgxUint8] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxUint8).Serialize()))
	ExpandedSgxCiphertextSize[SgxUint16] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxUint16).Serialize()))
	ExpandedSgxCiphertextSize[SgxUint32] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxUint32).Serialize()))
	ExpandedSgxCiphertextSize[SgxUint64] = uint(len(new(TsgxCiphertext).TrivialEncrypt(*big.NewInt(0), SgxUint64).Serialize()))

	compactSgxCiphertextSize[SgxBool] = uint(len(EncryptAndSerializeCompact(0, SgxBool)))
	compactSgxCiphertextSize[SgxUint4] = uint(len(EncryptAndSerializeCompact(0, SgxUint4)))
	compactSgxCiphertextSize[SgxUint8] = uint(len(EncryptAndSerializeCompact(0, SgxUint8)))
	compactSgxCiphertextSize[SgxUint16] = uint(len(EncryptAndSerializeCompact(0, SgxUint16)))
	compactSgxCiphertextSize[SgxUint32] = uint(len(EncryptAndSerializeCompact(0, SgxUint32)))
	compactSgxCiphertextSize[SgxUint64] = uint(len(EncryptAndSerializeCompact(0, SgxUint64)))
	compactSgxCiphertextSize[SgxUint160] = uint(len(EncryptAndSerializeCompact(0, SgxUint160)))
}

func InitGlobalKeysFromFiles(keysDir string) error {
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		return fmt.Errorf("init_keys: global keys directory doesn't exist (SGXVM_GO_KEYS_DIR): %s", keysDir)
	}
	// read keys from files
	var sksPath = path.Join(keysDir, "sks")
	sksBytes, err := os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	var pksPath = path.Join(keysDir, "pks")
	pksBytes, err := os.ReadFile(pksPath)
	if err != nil {
		return err
	}

	sks = C.deserialize_server_key(toDynamicBufferView(sksBytes))

	pksHash = crypto.Keccak256Hash(pksBytes)
	pks = C.deserialize_compact_public_key(toDynamicBufferView(pksBytes))

	initCiphertextSizes()

	fmt.Println("INFO: global keys loaded from: " + keysDir)

	return nil
}

// initialize keys automatically only if SGXVM_GO_KEYS_DIR is set
func init() {
	var keysDirPath, present = os.LookupEnv("SGXVM_GO_KEYS_DIR")
	if present {
		err := InitGlobalKeysFromFiles(keysDirPath)
		if err != nil {
			panic(err)
		}
		fmt.Println("INFO: global keys are initialized automatically using SGXVM_GO_KEYS_DIR env variable")
	} else {
		fmt.Println("INFO: global keys aren't initialized automatically (SGXVM_GO_KEYS_DIR env variable not set)")
	}
}
