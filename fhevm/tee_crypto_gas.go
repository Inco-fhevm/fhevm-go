package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func teeEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("teeEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := tfhe.FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}

func teeDecryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("teeDecrypt RequiredGas() input len must be 32 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("teeDecrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.TeeDecrypt[ct.fheUintType()]
}

func teeOptimisticRequireRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("optimisticRequire RequiredGas() input len must be 32 bytes",
			"input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("optimisticRequire RequiredGas() input doesn't point to verified ciphertext",
			"input", hex.EncodeToString(input))
		return 0
	}
	if ct.fheUintType() != tfhe.FheUint8 {
		logger.Error("optimisticRequire RequiredGas() ciphertext type is not FheUint8",
			"type", ct.fheUintType())
		return 0
	}
	if len(environment.FhevmData().optimisticRequires) == 0 {
		return environment.FhevmParams().GasCosts.TeeOptRequire[tfhe.FheUint8]
	}
	return environment.FhevmParams().GasCosts.TeeOptRequireBitAnd[tfhe.FheUint8]
}
