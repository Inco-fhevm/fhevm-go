package sgx

import "encoding/hex"

func sgxAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("sgxAdd/Sub RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.sgxUintType() != rhs.sgxUintType() {
		logger.Error("sgxAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.sgxUintType(), "rhs", rhs.sgxUintType())
		return 0
	}

	return environment.SgxParams().GasCosts.SgxAddSub[lhs.sgxUintType()]
}

func sgxMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("sgxMul RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.sgxUintType() != rhs.sgxUintType() {
		logger.Error("sgxMul RequiredGas() operand type mismatch", "lhs", lhs.sgxUintType(), "rhs", rhs.sgxUintType())
		return 0
	}
	return environment.SgxParams().GasCosts.SgxMul[lhs.sgxUintType()]
}

func sgxDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs *verifiedCiphertext

	lhs, _, err := getScalarOperands(environment, input)
	if err != nil {
		logger.Error("fheDiv RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	return environment.SgxParams().GasCosts.SgxScalarDiv[lhs.sgxUintType()]
}
