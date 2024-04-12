package fhevm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/sgx"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/nacl/box"
)

func verifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()
	// first 32 bytes of the payload is offset, then 32 bytes are size of byte array
	if len(input) <= 68 {
		err := errors.New("verifyCiphertext(bytes) must contain at least 68 bytes for selector, byte offset and size")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	bytesPaddingSize := 32
	bytesSizeSlotSize := 32
	// read only last 4 bytes of padded number for byte array size
	sizeStart := bytesPaddingSize + bytesSizeSlotSize - 4
	sizeEnd := sizeStart + 4
	bytesSize := binary.BigEndian.Uint32(input[sizeStart:sizeEnd])
	bytesStart := bytesPaddingSize + bytesSizeSlotSize
	bytesEnd := bytesStart + int(bytesSize)
	input = input[bytesStart:minInt(bytesEnd, len(input))]

	if len(input) <= 1 {
		msg := "verifyCiphertext Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ctBytes := input[:len(input)-1]
	ctTypeByte := input[len(input)-1]
	if !tfhe.IsValidFheType(ctTypeByte) {
		msg := "verifyCiphertext Run() ciphertext type is invalid"
		logger.Error(msg, "type", ctTypeByte)
		return nil, errors.New(msg)
	}
	ctType := tfhe.FheUintType(ctTypeByte)
	otelDescribeOperandsFheTypes(runSpan, ctType)

	expectedSize, found := tfhe.GetCompactFheCiphertextSize(ctType)
	if !found || expectedSize != uint(len(ctBytes)) {
		msg := "verifyCiphertext Run() compact ciphertext size is invalid"
		logger.Error(msg, "type", ctTypeByte, "size", len(ctBytes), "expectedSize", expectedSize)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ctType), nil
	}

	ct := new(tfhe.TfheCiphertext)
	err := ct.DeserializeCompact(ctBytes, ctType)
	if err != nil {
		logger.Error("verifyCiphertext failed to deserialize input ciphertext",
			"err", err,
			"len", len(ctBytes),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
		return nil, err
	}

	if tomlConfig.Fhevm.MockOpsFlag {
		logger.Info("[Caution!!] MockOpsFlag is enabled, decrypting ciphertext. Please make sure you're not using it in production.")
		plaintext, err := decryptValue(environment, ct)
		if err != nil {
			logger.Error("verifyCiphertext failed to decrypt input ciphertext")
			return nil, err
		}
		ct = new(tfhe.TfheCiphertext)
		pt := big.NewInt(int64(plaintext))
		ct = ct.TrivialEncrypt(*pt, ctType)
	}

	ctHash := ct.GetHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("verifyCiphertext success",
			"ctHash", ctHash.Hex(),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
	}
	return ctHash.Bytes(), nil
}

func classicalPublicKeyEncrypt(value *big.Int, userPublicKey []byte) ([]byte, error) {
	encrypted, err := box.SealAnonymous(nil, value.Bytes(), (*[32]byte)(userPublicKey), rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func encryptToUserKey(value *big.Int, pubKey []byte) ([]byte, error) {
	ct, err := classicalPublicKeyEncrypt(value, pubKey)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func reencryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(64, len(input))]
	// precompileBytes, err := reencryptRun(environment, caller, addr, bwCompatBytes, readOnly)

	logger := environment.GetLogger()
	if !environment.IsEthCall() {
		msg := "reencrypt only supported on EthCall"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 64 {
		msg := "reencrypt input len must be 64 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct != nil {
		otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

		decryptedValue, err := ct.ciphertext.Decrypt()
		if err != nil {
			logger.Error("reencrypt decryption failed", "err", err)
			return nil, err
		}
		pubKey := input[32:64]
		reencryptedValue, err := encryptToUserKey(&decryptedValue, pubKey)
		if err != nil {
			logger.Error("reencrypt failed to encrypt to user key", "err", err)
			return nil, err
		}

		// TODO: decide if `res.Signature` should be verified here

		logger.Info("reencrypt success", "input", hex.EncodeToString(input), "callerAddr", caller, "reencryptedValue", reencryptedValue, "len", len(reencryptedValue))
		reencryptedValue = toEVMBytes(reencryptedValue)
		// pad according to abi specification, first add offset to the dynamic bytes argument
		outputBytes := make([]byte, 32, len(reencryptedValue)+32)
		outputBytes[31] = 0x20
		outputBytes = append(outputBytes, reencryptedValue...)
		return padArrayTo32Multiple(outputBytes), nil
	}
	msg := "reencrypt unverified ciphertext handle"
	logger.Error(msg, "input", hex.EncodeToString(input))
	return nil, errors.New(msg)
}

func decryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	// if not gas estimation and not view function fail if decryptions are disabled in transactions
	if environment.IsCommitting() && !environment.IsEthCall() && environment.FhevmParams().DisableDecryptionsInTransaction {
		msg := "decryptions during transaction are disabled"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	if len(input) != 32 {
		msg := "decrypt input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "decrypt unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip decryption and make sure we return the maximum possible value.
	// We need that, because non-zero bytes cost more than zero bytes in some contexts (e.g. SSTORE or memory operations).
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return bytes.Repeat([]byte{0xFF}, 32), nil
	}

	plaintext, err := decryptValue(environment, ct.ciphertext)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}

	logger.Info("decrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	bigIntValue := big.NewInt(0)
	bigIntValue.SetUint64(plaintext)
	bigIntValue.FillBytes(ret)
	return ret, nil
}

func getCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(64, len(input))]

	logger := environment.GetLogger()
	if !environment.IsEthCall() {
		msg := "getCiphertext only supported on EthCall"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 64 {
		msg := "getCiphertext input len must be 64 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	contractAddress := common.BytesToAddress(input[:32])
	handle := common.BytesToHash(input[32:])

	ciphertext := getCiphertextFromProtectedStoage(environment, contractAddress, handle)
	if ciphertext == nil {
		return make([]byte, 0), nil
	}
	otelDescribeOperandsFheTypes(runSpan, ciphertext.metadata.fheUintType)
	return ciphertext.bytes, nil
}

func decryptValue(environment EVMEnvironment, ct *tfhe.TfheCiphertext) (uint64, error) {
	v, err := ct.Decrypt()
	return v.Uint64(), err
}

func castRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "cast Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("cast input not verified")
		return nil, errors.New("unverified ciphertext handle")
	}

	if !tfhe.IsValidFheType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := tfhe.FheUintType(input[32])

	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType(), castToType)

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, castToType), nil
	}

	res, err := ct.ciphertext.CastTo(castToType)
	if err != nil {
		msg := "cast Run() error casting ciphertext to"
		logger.Error(msg, "type", castToType)
		return nil, errors.New(msg)
	}

	resHash := res.GetHash()

	importCiphertext(environment, res)
	if environment.IsCommitting() {
		logger.Info("cast success",
			"ctHash", resHash.Hex(),
		)
	}

	return resHash.Bytes(), nil
}

var fhePubKeyHashPrecompile = common.BytesToAddress([]byte{93})
var fhePubKeyHashSlot = common.Hash{}

func fhePubKeyRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	existing := environment.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if existing != tfhe.GetPksHash() {
		msg := "fhePubKey FHE public key hash doesn't match one stored in state"
		environment.GetLogger().Error(msg, "existing", existing.Hex(), "pksHash", tfhe.GetPksHash().Hex())
		return nil, errors.New(msg)
	}
	// serialize public key
	pksBytes, err := tfhe.SerializePublicKey()
	if err != nil {
		return nil, err
	}
	// If we have a single byte with the value of 1, make as an EVM array.
	if len(input) == 1 && input[0] == 1 {
		pksBytes = toEVMBytes(pksBytes)
	}
	// pad according to abi specification, first add offset to the dynamic bytes argument
	outputBytes := make([]byte, 32, len(pksBytes)+32)
	outputBytes[31] = 0x20
	outputBytes = append(outputBytes, pksBytes...)
	return padArrayTo32Multiple(outputBytes), nil
}

func trivialEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "trivialEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := tfhe.FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	ct := new(tfhe.TfheCiphertext).TrivialEncrypt(valueToEncrypt, encryptToType)

	ctHash := ct.GetHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("trivialEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}

// SGX
func sgxEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "sgxEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := tfhe.FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	sgxPlaintext := sgx.NewSgxPlaintext(input[0:32], encryptToType, caller)

	ct, err := sgx.ToTfheCiphertext(sgxPlaintext)

	if err != nil {
		logger.Error("sgxEncrypt failed", "err", err)
		return nil, err
	}

	ctHash := ct.GetHash()
	importCiphertext(environment, &ct)
	if environment.IsCommitting() {
		logger.Info("sgxEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}

func sgxDecryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	// if not gas estimation and not view function fail if decryptions are disabled in transactions
	if environment.IsCommitting() && !environment.IsEthCall() && environment.FhevmParams().DisableDecryptionsInTransaction {
		msg := "decryptions during transaction are disabled"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	if len(input) != 32 {
		msg := "decrypt input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "decrypt unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip decryption and make sure we return the maximum possible value.
	// We need that, because non-zero bytes cost more than zero bytes in some contexts (e.g. SSTORE or memory operations).
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return bytes.Repeat([]byte{0xFF}, 32), nil
	}

	result, err := sgx.FromTfheCiphertext(*ct.ciphertext)
	plaintext := result.Plaintext

	if err != nil {
		logger.Error("sgxDecrypt failed", "err", err)
		return nil, err
	}

	logger.Info("sgxDecrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	copy(ret, plaintext)
	return ret, nil
}
