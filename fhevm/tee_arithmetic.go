package fhevm

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

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

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if lp.FheUintType == tfhe.FheUint128 || lp.FheUintType == tfhe.FheUint160 {
		panic("TODO implement me")
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

	result := operator(l, r)
	resultBz, err := marshalUint(result, lp.FheUintType)
	if err != nil {
		return nil, err
	}
	teePlaintext := tee.NewTeePlaintext(resultBz, lp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func teeAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("teeAddRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a + b
	})
}

func teeSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("teeSubRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a - b
	})
}

func teeMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a * b
	})
}

func teeDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a / b
	})
}

func teeRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doArithmeticOperation("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a % b
	})
}
