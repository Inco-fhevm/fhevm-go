package fhevm

func teeAddSubRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeAddSub", environment, input, environment.FhevmParams().GasCosts.TeeAddSub)
}

func teeMulRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeMul", environment, input, environment.FhevmParams().GasCosts.TeeMul)
}

func teeDivRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeDiv", environment, input, environment.FhevmParams().GasCosts.TeeDiv)
}

func teeRemRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeRem", environment, input, environment.FhevmParams().GasCosts.TeeRem)
}
