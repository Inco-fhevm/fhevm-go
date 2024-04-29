package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teeShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b, typ uint64) uint64 {
		switch typ {
		case 1:
			return uint64((uint8(a) << uint8(b)))
		case 2:
			return uint64((uint8(a) << uint8(b)))
		case 3:
			return uint64((uint16(a) << uint16(b)))
		case 4:
			return uint64((uint32(a) << uint32(b)))
		case 5:
			return (a << b)
		default:
			return 0
		}
	}, "teeShlRun")
}

func teeShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b, typ uint64) uint64 {
		switch typ {
		case 1:
			return uint64((uint8(a) >> uint8(b)))
		case 2:
			return uint64((uint8(a) >> uint8(b)))
		case 3:
			return uint64((uint16(a) >> uint16(b)))
		case 4:
			return uint64((uint32(a) >> uint32(b)))
		case 5:
			return (a >> b)
		default:
			return 0
		}
	}, "teeShrRun")
}

func teeRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b, typ uint64) uint64 {
		switch typ {
		case 1:
			return uint64((uint8(a) << uint8(b)) | (uint8(a) >> (uint8(4) - uint8(b)%4)))
		case 2:
			return uint64((uint8(a) << uint8(b)) | (uint8(a) >> (uint8(8) - uint8(b)%8)))
		case 3:
			return uint64((uint16(a) << uint16(b)) | (uint16(a) >> (uint16(16) - uint16(b)%16)))
		case 4:
			return uint64((uint32(a) << uint32(b)) | (uint32(a) >> (uint32(32) - uint32(b)%32)))
		case 5:
			return (a << b) | (a >> (64 - b%64))
		default:
			return 0
		}
	}, "teeRotl")
}

func teeRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOperationGeneric(environment, caller, input, runSpan, func(a, b, typ uint64) uint64 {
		switch typ {
		case 1:
			return uint64((uint8(a) >> uint8(b)) | (uint8(a) >> (uint8(4) - uint8(b)%4)))
		case 2:
			return uint64((uint8(a) >> uint8(b)) | (uint8(a) >> (uint8(8) - uint8(b)%8)))
		case 3:
			return uint64((uint16(a) >> uint16(b)) | (uint16(a) >> (uint16(16) - uint16(b)%16)))
		case 4:
			return uint64((uint32(a) >> uint32(b)) | (uint32(a) >> (uint32(32) - uint32(b)%32)))
		case 5:
			return (a >> b) | (a << (64 - b%64))
		default:
			return 0
		}
	}, "teeRotr")
}

func teeBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		switch a.(type) {
		case uint64:
			return a.(uint64) & b.(uint64)
		case bool:
			return a.(bool) && b.(bool)
		default:
			return nil
		}
	}, "teeBitAnd")
}

func teeBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		switch a.(type) {
		case uint64:
			return a.(uint64) | b.(uint64)
		case bool:
			return a.(bool) || b.(bool)
		default:
			return nil
		}
	}, "teeBitOr")
}

func teeBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		switch a.(type) {
		case uint64:
			return a.(uint64) ^ b.(uint64)
		case bool:
			return a.(bool) != b.(bool)
		default:
			return nil
		}
	}, "teeBitXor")
}

func teeNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a any) any {
		switch a := a.(type) {
		case uint64:
			return ^a + 1
		default:
			return nil
		}
	}, "teeNeg")
}

func teeNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a any) any {
		switch a := a.(type) {
		case uint64:
			return ^a
		case bool:
			return !a
		default:
			return nil
		}
	}, "teeNot")
}
