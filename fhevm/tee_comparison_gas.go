package fhevm

import (
	"encoding/hex"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func teeComparisonRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeComparison", environment, input, environment.FhevmParams().GasCosts.TeeComparison)
}

func teeSelectRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()

	first, second, third, err := get3VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("teeSelect op RequiredGas() inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if first.fheUintType() != tfhe.FheBool {
		logger.Error("teeSelect op RequiredGas() invalid type for condition", "first", first.fheUintType())
		return 0
	}
	if second.fheUintType() != third.fheUintType() {
		logger.Error("teeSelect op RequiredGas() operand type mismatch", "second", second.fheUintType(), "third", third.fheUintType())
		return 0
	}

	return environment.FhevmParams().GasCosts.TeeComparison[second.fheUintType()]
}
