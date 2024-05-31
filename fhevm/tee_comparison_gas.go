package fhevm

func teeComparisonRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	return teeOperationGas("teeComparison", environment, input, environment.FhevmParams().GasCosts.TeeComparison)
}
