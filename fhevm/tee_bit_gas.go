package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func teeShiftRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeShift", environment, input, environment.FhevmParams().GasCosts.TeeShift)
}

func teeBitwiseOpRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeBitwiseOp", environment, input, environment.FhevmParams().GasCosts.TeeBitwiseOp)
}

func teeNotRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeUnaryOperationGas("teeNot", environment, input, environment.FhevmParams().GasCosts.TeeNot)
}

func teeNegRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeUnaryOperationGas("teeNeg", environment, input, environment.FhevmParams().GasCosts.TeeNeg)
}

func teeUnaryOperationGas(_ string, environment EVMEnvironment, input []byte, gasCosts map[tfhe.FheUintType]uint64) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("teeNeg input needs to contain one 256-bit sized value", "input", hex.EncodeToString(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("teeNeg input not verified", "input", hex.EncodeToString(input))
		return 0
	}
	return gasCosts[ct.fheUintType()]
}
