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
		logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error(fmt.Sprintf("%s operand type mismatch", op), "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	lp, err := sgx.FromTfheCiphertext(lhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	rp, err := sgx.FromTfheCiphertext(rhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	return &lp, &rp, lhs, rhs, nil
}

func doArithmeticOperation(op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(uint64, uint64) uint64) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, err := extract2Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert th
	// result back to the FheUintType.
	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()

	resultPlaintext := operator(l, r)
	i := new(big.Int).SetUint64(resultPlaintext)

	sgxPlaintext := sgx.NewSgxPlaintext(i.Bytes(), lhs.fheUintType(), caller)

	resultCt, err := sgx.ToTfheCiphertext(sgxPlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func sgxAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxAddRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a + b
	})
}

func sgxSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxSubRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a - b
	})
}

func sgxMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("sgxMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a * b
	})
}
