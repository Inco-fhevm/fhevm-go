package fhevm

import (
	"fmt"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeShlRun(t *testing.T) {
	signature := "teeShl(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 4},
		{tfhe.FheUint8, 2, 2, 8},
		{tfhe.FheUint16, 4283, 3, 34264},
		{tfhe.FheUint32, 1333337, 4, 21333392},
		{tfhe.FheUint64, 13333377777777777, 5, 426668088888888864},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeShl with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}

func TestTeeShrRun(t *testing.T) {
	signature := "teeShr(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 2, 1070},
		{tfhe.FheUint32, 1333337, 3, 166667},
		{tfhe.FheUint64, 13333377777777777, 4, 833336111111111},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeShr with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature)
		})
	}
}
