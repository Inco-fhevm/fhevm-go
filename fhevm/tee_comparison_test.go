package fhevm

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func TestTeeLeRun(t *testing.T) {
	signature := "teeLe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 0},
		{tfhe.FheUint32, 1333337, 1337, 0},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 0},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeLtRun(t *testing.T) {
	signature := "teeLt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 0},
		{tfhe.FheUint8, 2, 1, 0},
		{tfhe.FheUint16, 4283, 1337, 0},
		{tfhe.FheUint32, 1333337, 1337, 0},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 0},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeLt with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeEqRun(t *testing.T) {
	signature := "teeEq(uint256,uint256,bytes1)"

	a, _ := new(big.Int).SetString("514178dd0EB0D239211867E8b5A01Ce8aF9f40c5", 16)
	b, _ := new(big.Int).SetString("125486dd0EB0D239211867E8b5A01Ce8aF9f53c5", 16)

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      *big.Int
		rhs      *big.Int
		expected bool
	}{
		{tfhe.FheUint4, big.NewInt(2), big.NewInt(1), false},
		{tfhe.FheUint8, big.NewInt(2), big.NewInt(1), false},
		{tfhe.FheUint16, big.NewInt(4283), big.NewInt(1337), false},
		{tfhe.FheUint32, big.NewInt(1333337), big.NewInt(1337), false},
		{tfhe.FheUint64, big.NewInt(13333377777777777), big.NewInt(133377777777), false},
		{tfhe.FheUint160, a, b, false},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeEq with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeGeRun(t *testing.T) {
	signature := "teeGe(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1},
		{tfhe.FheUint32, 1333337, 1337, 1},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeGtRun(t *testing.T) {
	signature := "teeGt(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1},
		{tfhe.FheUint32, 1333337, 1337, 1},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeGt with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeNeRun(t *testing.T) {
	signature := "teeNe(uint256,uint256,bytes1)"

	a, _ := new(big.Int).SetString("514178dd0EB0D239211867E8b5A01Ce8aF9f40c5", 16)
	b, _ := new(big.Int).SetString("125486dd0EB0D239211867E8b5A01Ce8aF9f53c5", 16)

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      *big.Int
		rhs      *big.Int
		expected uint64
	}{
		{tfhe.FheUint4, big.NewInt(2), big.NewInt(1), 1},
		{tfhe.FheUint8, big.NewInt(2), big.NewInt(1), 1},
		{tfhe.FheUint16, big.NewInt(4283), big.NewInt(1337), 1},
		{tfhe.FheUint32, big.NewInt(1333337), big.NewInt(1337), 1},
		{tfhe.FheUint64, big.NewInt(13333377777777777), big.NewInt(133377777777), 1},
		{tfhe.FheUint160, a, b, 1},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeNe with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeMinRun(t *testing.T) {
	signature := "teeMin(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 1},
		{tfhe.FheUint8, 2, 1, 1},
		{tfhe.FheUint16, 4283, 1337, 1337},
		{tfhe.FheUint32, 1333337, 1337, 1337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 133377777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMin with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeMaxRun(t *testing.T) {
	signature := "teeMax(uint256,uint256,bytes1)"

	testcases := []struct {
		typ      tfhe.FheUintType
		lhs      uint64
		rhs      uint64
		expected uint64
	}{
		{tfhe.FheUint4, 2, 1, 2},
		{tfhe.FheUint8, 2, 1, 2},
		{tfhe.FheUint16, 4283, 1337, 4283},
		{tfhe.FheUint32, 1333337, 1337, 1333337},
		{tfhe.FheUint64, 13333377777777777, 133377777777, 13333377777777777},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeMax with %s", tc.typ), func(t *testing.T) {
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, false)
			// scalar operations
			teeOperationHelper(t, tc.typ, tc.lhs, tc.rhs, tc.expected, signature, true)
		})
	}
}

func TestTeeSelectRun(t *testing.T) {
	signature := "teeSelect(uint256,uint256,uint256)"

	a, _ := new(big.Int).SetString("514178dd0EB0D239211867E8b5A01Ce8aF9f40c5", 16)
	b, _ := new(big.Int).SetString("125486dd0EB0D239211867E8b5A01Ce8aF9f53c5", 16)

	testcases := []struct {
		typ      tfhe.FheUintType
		fhs      bool
		shs      *big.Int
		ths      *big.Int
		expected *big.Int
	}{
		{tfhe.FheUint4, true, big.NewInt(2), big.NewInt(1), big.NewInt(2)},
		{tfhe.FheUint8, true, big.NewInt(2), big.NewInt(1), big.NewInt(2)},
		{tfhe.FheUint16, true, big.NewInt(4283), big.NewInt(1337), big.NewInt(4283)},
		{tfhe.FheUint32, true, big.NewInt(1333337), big.NewInt(1337), big.NewInt(1333337)},
		{tfhe.FheUint64, true, big.NewInt(13333377777777777), big.NewInt(133377777777), big.NewInt(13333377777777777)},
		{tfhe.FheUint160, true, a, b, a},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("teeSelect with %s", tc.typ), func(t *testing.T) {
			teeSelectOperationHelper(t, tc.typ, tc.fhs, tc.shs, tc.ths, tc.expected, signature)
		})
	}
}
