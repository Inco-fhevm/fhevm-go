package fhevm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

func teeEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "teeEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := tfhe.FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	teePlaintext := tee.NewTeePlaintext(input[0:32], encryptToType, caller)

	ct, err := tee.Encrypt(teePlaintext)

	if err != nil {
		logger.Error("teeEncrypt failed", "err", err)
		return nil, err
	}

	ctHash := ct.GetHash()
	importCiphertext(environment, &ct)
	if environment.IsCommitting() {
		logger.Info("teeEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}

func teeDecryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
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

	result, err := tee.Decrypt(ct.ciphertext)
	if err != nil {
		logger.Error("teeDecrypt failed", "err", err)
		return nil, err
	}
	plaintext := result.Value

	logger.Info("teeDecrypt success", "plaintext", plaintext)

	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	copy(ret[32-len(plaintext):], plaintext)
	return ret, nil
}

func teeVerifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
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
