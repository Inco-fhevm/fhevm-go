package fhevm

import "encoding/hex"

func teeArithmeticGas(op string, environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error(op, "RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error(op, "RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}

	var cost uint64

	switch op {
	case "teeAddSub":
		cost = environment.FhevmParams().GasCosts.TeeAddSub[lhs.fheUintType()]
	case "teeMul":
		cost = environment.FhevmParams().GasCosts.TeeMul[lhs.fheUintType()]
	case "teeDiv":
		cost = environment.FhevmParams().GasCosts.TeeDiv[lhs.fheUintType()]
	case "teeRem":
		cost = environment.FhevmParams().GasCosts.TeeRem[lhs.fheUintType()]
	default:
		cost = 0
	}

	return cost
}

func teeAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeArithmeticGas("teeAddSub", environment, input)
}

func teeMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeArithmeticGas("teeMul", environment, input)
}

func teeDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeArithmeticGas("teeDiv", environment, input)
}

func teeRemRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeArithmeticGas("teeRem", environment, input)
}