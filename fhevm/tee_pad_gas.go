package fhevm

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teePadGasRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {

	input = input[:minInt(32, len(input))]

	gasLimit := environment.GasLimit()
	consumedGas := gasLimit - suppliedGas

	padTo := new(big.Int).SetBytes(input)

	if consumedGas > padTo.Uint64() {
		return 0
	}

	return padTo.Uint64() - consumedGas

}

func teePadGasRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return nil, nil
}
