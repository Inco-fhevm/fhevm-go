package fhevm

import (
	"bytes"
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

	// Make sure we don't decrypt before any optimistic requires are checked.
	optReqResult, optReqErr := teeEvaluateRemainingOptimisticRequires(environment)
	if optReqErr != nil {
		return nil, optReqErr
	} else if !optReqResult {
		return nil, ErrExecutionReverted
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

func teeOptimisticRequireRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		msg := "optimisticRequire input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "optimisticRequire unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())
	// If we are doing gas estimation, don't do anything as we would assume all requires are true.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return nil, nil
	}
	if ct.fheUintType() != tfhe.FheUint8 {
		msg := "optimisticRequire ciphertext type is not FheUint8"
		logger.Error(msg, "type", ct.fheUintType())
		return nil, errors.New(msg)
	}
	environment.FhevmData().appendTeeOptimisticRequires(ct.ciphertext)
	return nil, nil
}

// If there are optimistic requires, check them by doing bitwise AND on all of them.
// That works, because we assume their values are either 0 or 1. If there is at least
// one 0, the result will be 0 (false).
func teeEvaluateRemainingOptimisticRequires(environment EVMEnvironment) (bool, error) {
	requires := environment.FhevmData().optimisticRequires
	length := len(requires)
	defer func() { environment.FhevmData().resetTeeOptimisticRequires() }()
	if length != 0 {
		cumulative := uint64(1)
		for i := 0; i < length; i++ {
			lp, err := tee.Decrypt(requires[i])
			if err != nil {
				environment.GetLogger().Error("evaluateRemainingOptimisticRequires bitand failed", "err", err)
				return false, err
			}

			l := new(big.Int).SetBytes(lp.Value).Uint64()
			cumulative = cumulative & l
			// if it is 0 at any moment, it can return with result false
			if cumulative == 0 {
				return false, nil
			}
		}
	}
	return true, nil
}
