package fhevm

import (
	"testing"

	"github.com/holiman/uint256"
	"pgregory.net/rapid"
)

func TestTeePadRequiredGas(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		testcases := []struct {
			suppliedGas uint64
			padTo       uint256.Int
			expected    uint64
		}{
			{40, *uint256.NewInt(20), 0},
			{90, *uint256.NewInt(110), 100},
			{10, *uint256.NewInt(90), 0},
			{50, *uint256.NewInt(90), 40},
		}
		for _, tc := range testcases {
			environment := newTestEVMEnvironment()
			environment.gasLimit = 100

			padToBytes := tc.padTo.Bytes()
			result := teePadGasRequiredGas(environment, tc.suppliedGas, padToBytes)
			if result != tc.expected {
				t.Fatalf("incorrect result, expected=%d, got=%d", tc.expected, result)
			}
		}
	})
}
