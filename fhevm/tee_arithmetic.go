package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teeAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) + b.(uint64)
	}, "teeAddRun")
}

func teeSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) - b.(uint64)
	}, "teeSubRun")
}

func teeMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) * b.(uint64)
	}, "teeMulRun")
}

func teeDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) / b.(uint64)
	}, "teeDivRun")
}

func teeRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b any) any {
		return a.(uint64) % b.(uint64)
	}, "teeRemRun")
}
