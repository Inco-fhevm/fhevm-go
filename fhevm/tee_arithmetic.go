package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teeAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric("teeAddRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a + b
	})
}

func teeSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric("teeSubRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a - b
	})
}

func teeMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a * b
	})
}

func teeDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a / b
	})
}

func teeRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric("teeMulRun", environment, caller, input, runSpan, func(a uint64, b uint64) uint64 {
		return a % b
	})
}
