package sgx

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func sgxAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("sgxAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.sgxUintType() != rhs.sgxUintType() {
		msg := "sgxAdd operand type mismatch"
		logger.Error(msg, "lhs", lhs.sgxUintType(), "rhs", rhs.sgxUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.sgxUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l + r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.sgxUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("sgxAdd failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxAdd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}

func sgxSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("sgxSub inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.sgxUintType() != rhs.sgxUintType() {
		msg := "sgxSub operand type mismatch"
		logger.Error(msg, "lhs", lhs.sgxUintType(), "rhs", rhs.sgxUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.sgxUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l - r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.sgxUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("sgxSub failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxMul success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}

func sgxMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("sgxMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.sgxUintType() != rhs.sgxUintType() {
		msg := "sgxMul operand type mismatch"
		logger.Error(msg, "lhs", lhs.sgxUintType(), "rhs", rhs.sgxUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.sgxUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l * r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.sgxUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("sgxAdd failed", "err", err)
		return nil, err
	}
	return result, nil
}

func sgxDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := getScalarOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
	if err != nil {
		logger.Error("sgxDiv scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.sgxUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l - r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.sgxUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("sgxDiv failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxDiv success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}
