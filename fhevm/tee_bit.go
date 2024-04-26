package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teeShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) << b.(uint64)
	}, "teeShlRun")
}

func teeShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) >> b.(uint64)
	}, "teeShrRun")
}

func teeRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return (a.(uint64) << b.(uint64)) | (a.(uint64) >> (8 - b.(uint64)%8))
	}, "teeRotl")
}

func teeRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return (a.(uint64) >> b.(uint64)) | (a.(uint64) << (8 - b.(uint64)%8))
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

func teeNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a any) any {
		switch a.(type) {
		case uint64:
			return ^a.(uint64)
		case bool:
			return !a.(bool)
		default:
			return nil
		}
	}, "teeNot")
}

func teeNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOperationGeneric(environment, caller, input, runSpan, func(a any) any {
		switch a.(type) {
		case uint64:
			return ^a.(uint64) + 1
		default:
			return nil
		}
	}, "teeNeg")
}
