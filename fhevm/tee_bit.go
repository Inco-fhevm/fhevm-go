package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
)

func teeShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) uint64 {
		switch typ {
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 << b1)
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 << b1)
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64(a1 << b1)
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64(a1 << b1)
		case 5:
			return a << b
		default:
			return 0
		}
	}, "teeShlRun")
}

func teeShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) uint64 {
		switch typ {
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 >> b1)
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64(a1 >> b1)
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64(a1 >> b1)
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64(a1 >> b1)
		case 5:
			return (a >> b)
		default:
			return 0
		}
	}, "teeShrRun")
}

func teeRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) uint64 {
		switch typ {
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 << b1) | (a1 >> (uint8(4) - b1%4)))
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 << b1) | (a1 >> (uint8(8) - b1%8)))
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64((a1 << b1) | (a1 >> (uint16(16) - b1%16)))
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64((a1 << b1) | (a1 >> (uint32(32) - b1%32)))
		case 5:
			return (a << b) | (a >> (64 - b%64))
		default:
			return 0
		}
	}, "teeRotl")
}

func teeRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) uint64 {
		switch typ {
		case 1:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 >> b1) | (a1 << (uint8(4) - b1%4)))
		case 2:
			a1, b1 := uint8(a), uint8(b)
			return uint64((a1 >> b1) | (a1 << (uint8(8) - b1%8)))
		case 3:
			a1, b1 := uint16(a), uint16(b)
			return uint64((a1 >> b1) | (a1 << (uint16(16) - b1%16)))
		case 4:
			a1, b1 := uint32(a), uint32(b)
			return uint64((a1 >> b1) | (a1 << (uint32(32) - b1%32)))
		case 5:
			return (a >> b) | (a << (64 - b%64))
		default:
			return 0
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
