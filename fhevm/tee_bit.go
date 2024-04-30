package fhevm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
)

func teeShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 << b1), nil
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 << b1), nil
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64(a1 << b1), nil
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64(a1 << b1), nil
		case 5:
			return a << b, nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeShlRun")
}

func teeShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 >> b1), nil
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 >> b1), nil
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64(a1 >> b1), nil
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64(a1 >> b1), nil
		case 5:
			return (a >> b), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeShrRun")
}

func teeRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 << b1) | (a1 >> (uint8(4) - b1%4))), nil
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 << b1) | (a1 >> (uint8(8) - b1%8))), nil
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64((a1 << b1) | (a1 >> (uint16(16) - b1%16))), nil
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64((a1 << b1) | (a1 >> (uint32(32) - b1%32))), nil
		case 5:
			return (a << b) | (a >> (64 - b%64)), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeRotl")
}

func teeRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 >> b1) | (a1 << (uint8(4) - b1%4))), nil
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 >> b1) | (a1 << (uint8(8) - b1%8))), nil
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64((a1 >> b1) | (a1 << (uint16(16) - b1%16))), nil
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64((a1 >> b1) | (a1 << (uint32(32) - b1%32))), nil
		case 5:
			return (a >> b) | (a << (64 - b%64)), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeRotr")
}

func teeBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a & b
	}, "teeBitAnd")
}

func teeBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a | b
	}, "teeBitOr")
}

func teeBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a ^ b
	}, "teeBitXor")
}

func teeNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a uint64) uint64 {
		return ^a + 1
	}, "teeNeg")
}

func teeNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a uint64) uint64 {
		return ^a
	}, "teeNot")
}
