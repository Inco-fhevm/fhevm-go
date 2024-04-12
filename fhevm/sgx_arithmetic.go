package fhevm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/sgx"
	"go.opentelemetry.io/otel/trace"
)

func extract2Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*sgx.SgxPlaintext, *sgx.SgxPlaintext, *verifiedCiphertext, *verifiedCiphertext, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error(op, "inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error(op, "operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	// if !environment.IsCommitting() && !environment.IsEthCall() {
	// 	return importRandomCiphertext(environment, lhs.fheUintType()), nil
	// }

	lb, err := sgx.FromTfheCiphertext(lhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	rb, err := sgx.FromTfheCiphertext(rhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	return &lb, &rb, lhs, rhs, nil
}

func sgxAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	lb, rb, lhs, rhs, err := extract2Operands("sgxAdd", environment, input, runSpan)
	if err != nil {
		logger.Error("sgxAdd failed", "err", err)
		return nil, err
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	l := big.NewInt(0).SetBytes(lb.Plaintext).Uint64()
	r := big.NewInt(0).SetBytes(rb.Plaintext).Uint64()

	resultPlaintext := l + r

	resultPlaintextByte := make([]byte, 32)
	resultByte := big.NewInt(0)
	resultByte.SetUint64(resultPlaintext)
	resultByte.FillBytes(resultPlaintextByte)

	sgxPlaintext := sgx.NewSgxPlaintext(resultPlaintextByte, lhs.fheUintType(), caller)

	result, err := sgx.ToTfheCiphertext(sgxPlaintext)

	if err != nil {
		logger.Error("sgxAdd failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &result)

	resultHash := result.GetHash()
	logger.Info("sgxAdd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func sgxSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	lb, rb, lhs, rhs, err := extract2Operands("sgxSub", environment, input, runSpan)
	if err != nil {
		logger.Error("sgxSub failed", "err", err)
		return nil, err
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	l := big.NewInt(0).SetBytes(lb.Plaintext).Uint64()
	r := big.NewInt(0).SetBytes(rb.Plaintext).Uint64()

	resultPlaintext := l - r

	resultPlaintextByte := make([]byte, 32)
	resultByte := big.NewInt(0)
	resultByte.SetUint64(resultPlaintext)
	resultByte.FillBytes(resultPlaintextByte)

	sgxPlaintext := sgx.NewSgxPlaintext(resultPlaintextByte, lhs.fheUintType(), caller)

	result, err := sgx.ToTfheCiphertext(sgxPlaintext)

	if err != nil {
		logger.Error("sgxSub failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &result)

	resultHash := result.GetHash()
	logger.Info("sgxSub success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func sgxMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	lb, rb, lhs, rhs, err := extract2Operands("sgxMul", environment, input, runSpan)
	if err != nil {
		logger.Error("sgxMul failed", "err", err)
		return nil, err
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	l := big.NewInt(0).SetBytes(lb.Plaintext).Uint64()
	r := big.NewInt(0).SetBytes(rb.Plaintext).Uint64()

	resultPlaintext := l * r

	resultPlaintextByte := make([]byte, 32)
	resultByte := big.NewInt(0)
	resultByte.SetUint64(resultPlaintext)
	resultByte.FillBytes(resultPlaintextByte)

	sgxPlaintext := sgx.NewSgxPlaintext(resultPlaintextByte, lhs.fheUintType(), caller)

	result, err := sgx.ToTfheCiphertext(sgxPlaintext)

	if err != nil {
		logger.Error("sgxMul failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &result)

	resultHash := result.GetHash()
	logger.Info("sgxMul success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}
