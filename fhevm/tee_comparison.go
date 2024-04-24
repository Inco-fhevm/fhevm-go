package fhevm

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

func doComparison1Operation(op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(uint64, uint64) bool) ([]byte, error) {
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
	resultBz, err := marshalBool(result)
	if err != nil {
		return nil, err
	}
	teePlaintext := tee.NewTeePlaintext(resultBz, 0, caller)

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

func doComparison2Operation(op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(uint64, uint64) uint64) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, err := extract2Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lp.FheUintType), nil
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

func doComparison3Operation(op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(bool, uint64, uint64) uint64) ([]byte, error) {
	logger := environment.GetLogger()

	fp, sp, tp, fhs, shs, ths, err := extract3Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, sp.FheUintType), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if sp.FheUintType == tfhe.FheUint128 || sp.FheUintType == tfhe.FheUint160 {
		panic("TODO implement me")
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert th
	// result back to the FheUintType.
	var f bool
	if fp.Value[0] == 1 {
		f = true
	} else {
		f = false
	}
	s := big.NewInt(0).SetBytes(sp.Value).Uint64()
	t := big.NewInt(0).SetBytes(tp.Value).Uint64()

	result := operator(f, s, t)
	resultBz, err := marshalUint(result, sp.FheUintType)
	if err != nil {
		return nil, err
	}
	teePlaintext := tee.NewTeePlaintext(resultBz, sp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "fhs", fhs.hash().Hex(), "shs", shs.hash().Hex(), "ths", ths.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func teeLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeLeRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a <= b
	})
}

func teeLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeLtRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a < b
	})
}

func teeEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeEqRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a == b
	})
}

func teeGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeGeRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a >= b
	})
}

func teeGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeGtRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a > b
	})
}

func teeNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison1Operation("teeNeRun", environment, caller, input, runSpan, func(a uint64, b uint64) bool {
		return a != b
	})
}

func teeMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison2Operation("teeMinRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		if a >= b {
			return b
		} else {
			return a
		}
	})
}

func teeMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison2Operation("teeMaxRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		if a >= b {
			return a
		} else {
			return b
		}
	})
}

func teeCmuxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doComparison3Operation("teeIfThenElseRun", environment, caller, input, runSpan, func(f bool, s uint64, t uint64) uint64 {
		if f {
			return s
		} else {
			return t
		}
	})
}