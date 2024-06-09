package fhevm

func teeCastRequiredGas(environment EVMEnvironment, suppliedGas uint64, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	if len(input) != 33 {
		environment.GetLogger().Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.TeeCast
}
